/*    Copyright 2026 Firewalla Inc.
 *
 *    This program is free software: you can redistribute it and/or  modify
 *    it under the terms of the GNU Affero General Public License, version 3,
 *    as published by the Free Software Foundation.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU Affero General Public License for more details.
 *
 *    You should have received a copy of the GNU Affero General Public License
 *    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
'use strict';

// Captive portal for MAB SSIDs. The portal network is the SSID's MAB default network: it can't
// reach anything, and HTTP from it gets an OK page. OK allows the device's MAC on the SSID with
// the internet network in fwapc, then kicks the device, so it re-joins on that network.
//
// network policy: captivePortal: { state: true, profileId: <SSID profile>, internetNetwork: <uuid>,
//   port? }

const log = require('../net2/logger.js')(__filename);
const http = require('http');
const fs = require('fs');
const path = require('path');
const iptool = require('ip');
const execAsync = require('child-process-promise').exec;
const Sensor = require('./Sensor.js').Sensor;
const extensionManager = require('./ExtensionManager.js');
const NetworkProfile = require('../net2/NetworkProfile.js');
const NetworkProfileManager = require('../net2/NetworkProfileManager.js');
const { Rule } = require('../net2/Iptables.js');
const iptc = require('../control/IptablesControl.js');
const fwapc = require('../net2/fwapc.js');
const HostTool = require('../net2/HostTool.js');
const hostTool = new HostTool();

const POLICY_NAME = 'captivePortal';
const NAT_CHAIN = 'FW_PREROUTING_CAPTIVE';
const FWD_CHAIN = 'FW_FORWARD_CAPTIVE';
const DEFAULT_PORT = 8890;
// hostapd keeps a RADIUS answer ~30s; a kick sooner puts the device back on the portal network
const RADIUS_CACHE_SECS = 31;
// time for the OK reply page to reach the device before it is kicked
const REPLY_SECS = 2;

// the page shell with a {{content}} slot, and the content of each page
const PAGE_DIR = path.join(__dirname, '../extension/captiveportal');
const PAGES = ['page', 'login', 'done', 'error'];

class CaptivePortalPlugin extends Sensor {
  async run() {
    // network uuid -> { policy, server, ip }
    this.portals = {};
    this.pages = {};
    for (const name of PAGES)
      this.pages[name] = fs.readFileSync(path.join(PAGE_DIR, `${name}.html`), 'utf8');
    for (const fam of [4, 6]) {
      for (const table of ['nat', 'filter'])
        await iptc.addRule(new Rule(table).fam(fam).chn(table == 'nat' ? NAT_CHAIN : FWD_CHAIN).opr('-N'));
      await iptc.addRule(new Rule('nat').fam(fam).chn('FW_PREROUTING').jmp(NAT_CHAIN).opr('-I'));
      await iptc.addRule(new Rule('filter').fam(fam).chn('FW_FORWARD').jmp(FWD_CHAIN).opr('-I'));
    }

    extensionManager.registerExtension(POLICY_NAME, this, {
      applyPolicy: this.applyPolicy,
    });
  }

  async applyPolicy(monitorable, ip, policy) {
    if (!(monitorable instanceof NetworkProfile)) return;
    const uuid = monitorable.getUniqueId();
    try {
      await this.stop(uuid);
      if (policy && policy.state === true && policy.profileId && policy.internetNetwork)
        await this.start(monitorable, policy);
    } catch (err) {
      log.error(`Failed to apply captive portal on ${uuid}`, err.message);
    }
  }

  // by the portal interface, not its subnets, so a device that kept an address from another
  // network (iOS re-join check) is isolated too
  rules(intf, port) {
    const fams = [4, 6];
    return [
      new Rule('nat').chn(NAT_CHAIN).iif(intf).pro('tcp').dport(80).jmp(`REDIRECT --to-ports ${port}`),
      // all DNS goes to the box's DNS on this network, also a device's own resolver (e.g. 8.8.8.8)
      // and also when DNS Booster is off, whose fallback would send it upstream and be dropped
      ...fams.flatMap(fam => ['udp', 'tcp'].map(p => new Rule('nat').fam(fam).chn(NAT_CHAIN).iif(intf)
        .pro(p).dport(53).jmp('REDIRECT --to-ports 53'))),
      // HTTPS can't be redirected without a certificate error, so fail it fast; the page is IPv4
      // only, so all IPv6 TCP is reset and captive checks fall back to IPv4
      new Rule('filter').chn(FWD_CHAIN).iif(intf).pro('tcp').dport(443).jmp('REJECT --reject-with tcp-reset'),
      new Rule('filter').fam(6).chn(FWD_CHAIN).iif(intf).pro('tcp').jmp('REJECT --reject-with tcp-reset'),
      ...fams.flatMap(fam => [
        new Rule('filter').fam(fam).chn(FWD_CHAIN).iif(intf).jmp('DROP'),
        new Rule('filter').fam(fam).chn(FWD_CHAIN).oif(intf).jmp('DROP'),
      ]),
    ];
  }

  async start(network, policy) {
    const uuid = network.getUniqueId();
    const ip = network.o.ipv4;
    if (!ip) throw new Error('network has no IPv4 address');
    const port = Number(policy.port) || DEFAULT_PORT;
    const inet = NetworkProfileManager.getNetworkProfile(policy.internetNetwork);
    if (!inet || !inet.o.intf) throw new Error(`no internet network ${policy.internetNetwork}`);
    const intf = network.o.intf;
    for (const rule of this.rules(intf, port)) await iptc.addRule(rule.opr('-A'));

    const server = http.createServer((req, res) => this.handle(uuid, req, res));
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, ip, resolve);
    });
    // granted: MAC -> { kickAt } while its kick is pending
    this.portals[uuid] = { policy, server, port, intf, subnets: network.o.ipv4Subnets || [], inetIntf: inet.o.intf, granted: {} };
    for (const arpIntf of [intf, inet.o.intf])
      await this.setArpIgnore(arpIntf, 1).catch(err =>
        log.warn(`Failed to set arp_ignore on ${arpIntf}`, err.message));
    log.info(`Captive portal on ${network.o.intf} ${ip}:${port}, then ${inet.o.intf}`);
  }

  // Restrict gateway ARP replies on both VLANs so rejoining clients detect the network
  // change instead of keeping an address from the previous VLAN.
  async setArpIgnore(intf, value) {
    // the proc path keeps a dotted VLAN interface name as it is
    await execAsync(`echo ${value} | sudo tee /proc/sys/net/ipv4/conf/${intf}/arp_ignore`);
  }

  async stop(uuid) {
    const portal = this.portals[uuid];
    if (!portal) return;
    delete this.portals[uuid];
    for (const rule of this.rules(portal.intf, portal.port)) await iptc.addRule(rule.opr('-D'));
    portal.server.close();
    for (const intf of [portal.intf, portal.inetIntf]) {
      if (!Object.values(this.portals).some(x => x.intf === intf || x.inetIntf === intf))
        await this.setArpIgnore(intf, 0).catch(err =>
          log.warn(`Failed to restore arp_ignore on ${intf}`, err.message));
    }
    log.info(`Captive portal off on ${uuid}`);
  }

  reply(res, code, name, vars = {}) {
    let content = this.pages[name];
    for (const [k, v] of Object.entries(vars)) content = content.split(`{{${k}}}`).join(String(v));
    const html = this.pages.page.replace('{{content}}', content);
    res.writeHead(code, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(html);
  }

  async handle(uuid, req, res) {
    try {
      // any GET, including OS captive checks, gets the page, which opens the sign-in sheet
      if (req.method !== 'POST' || req.url.split('?')[0] !== '/ok')
        return this.reply(res, 200, 'login');
      const wait = await this.grant(uuid, req.socket.remoteAddress.replace(/^::ffff:/, ''));
      this.reply(res, 200, 'done', { wait });
    } catch (err) {
      log.warn('Captive portal request failed', err.message);
      this.reply(res, 500, 'error');
    }
  }

  async macOf(ip) {
    const mac = await hostTool.getMacByIPWithCache(ip);
    if (mac) return mac.toUpperCase();
    // a device that just joined may not be a known host yet
    const out = await execAsync(`ip neigh show ${ip}`).then(r => r.stdout).catch(() => '');
    const m = out.match(/lladdr ([0-9a-f:]{17})/i);
    return m && m[1].toUpperCase();
  }

  // returns the seconds until the device is kicked
  async grant(uuid, ip) {
    const portal = this.portals[uuid];
    if (!portal) throw new Error('portal is off');
    // the box address is reachable from other LANs too; only devices on the portal network
    if (!portal.subnets.some(x => iptool.cidrSubnet(x).contains(ip)))
      throw new Error(`${ip} is not on the portal network`);
    const mac = await this.macOf(ip);
    if (!mac) throw new Error(`no MAC for ${ip}`);
    // OK again while it waits (the sign-in sheet may still be open): same countdown, nothing new
    const granted = portal.granted[mac];
    if (granted && granted.kickAt > Date.now() / 1000)
      return Math.ceil(granted.kickAt - Date.now() / 1000);
    const { profileId, internetNetwork } = portal.policy;
    // before the allow, which drops the device's accepted record
    const accepted = await fwapc.apiCall('GET', '/mac_auth/accepted');
    const record = accepted.code === 200 && Array.isArray(accepted.body)
      && accepted.body.find(x => x.mac === mac);
    // no record: kick after the full cache time rather than right away
    const lastSeen = (record && record.lastSeen) || Date.now() / 1000;
    const r = await fwapc.apiCall('POST', '/mac_auth/allowed',
      { mac, ssids: [profileId], network: internetNetwork, name: 'captive portal' });
    if (r.code !== 200) throw new Error(`allow ${mac}: ${r.code} ${JSON.stringify(r.body || r.msg)}`);
    // The AP keeps the portal answer cached on the device's BSS for RADIUS_CACHE_SECS. Its fwap
    // lets the device in with the internet VLAN from hostapd's accept list (checked before that
    // cache) and kicks it, so it re-joins there at once; an older fwap blocks the BSS instead.
    // Without that, kick it once the cache expired.
    const kickAt = Math.max(Date.now() / 1000 + REPLY_SECS, lastSeen + RADIUS_CACHE_SECS);
    portal.granted[mac] = { kickAt };
    setTimeout(() => this.kick(portal, mac, kickAt).catch(err =>
      log.warn(`Captive portal kick ${mac} failed`, err.message)), REPLY_SECS * 1000);
    return Math.ceil(kickAt - Date.now() / 1000);
  }

  // the VLAN of a box network the APs carry, 0 when untagged; undefined when not carried
  async vlanOf(intf) {
    const config = await fwapc.apiCall('GET', '/config/active');
    return Object.values((config.body && config.body.assets_template) || {})
      .flatMap(t => t.wifiNetworks || [])
      .filter(n => n.intf === intf)
      .map(n => n.vlan || 0)[0];
  }

  async kick(portal, mac, kickAt) {
    const wait = Math.max(0, Math.ceil(kickAt - Date.now() / 1000));
    const vlan = await this.vlanOf(portal.inetIntf);
    if (wait > 0 && vlan !== undefined) {
      const b = await fwapc.apiCall('POST', '/control/block_station', { mac, duration: wait, vlan });
      if (b.code === 200) {
        log.info(`Captive portal granted ${mac}, let in with VLAN ${vlan} and kicked`);
        // an fwap without the accept list only blocked it, and its station control may lift that
        // block while the portal answer is still cached
        setTimeout(() => this.recheck(portal, mac).catch(err =>
          log.warn(`Captive portal recheck ${mac} failed`, err.message)), (wait + 2) * 1000);
        delete portal.granted[mac];
        return;
      }
      log.info(`Captive portal block_station ${mac}: ${b.code}, kick in ${wait}s instead`);
    }
    await new Promise(resolve => setTimeout(resolve, wait * 1000));
    delete portal.granted[mac];
    const k = await fwapc.apiCall('POST', `/control/steer/${mac}`);
    log.info(`Captive portal granted ${mac}, kicked after ${wait}s: ${k.code}`);
    setTimeout(() => this.recheck(portal, mac).catch(err =>
      log.warn(`Captive portal recheck ${mac} failed`, err.message)), (RADIUS_CACHE_SECS + 2) * 1000);
  }

  // kicks the device again if it is still on the portal network's VLAN; its next join gets a fresh
  // RADIUS answer
  async recheck(portal, mac, tries = 0) {
    const [stations, vlan] = await Promise.all([
      fwapc.apiCall('GET', '/status/station'),
      this.vlanOf(portal.intf),
    ]);
    const station = stations.code === 200 && stations.body && stations.body.info && stations.body.info[mac];
    if (!station || !station.intf || vlan === undefined) return;
    const current = station.dvlanVlanId || station.vlanId || 0;
    if (current !== vlan) return;
    // fwapc takes a station's VLAN from the AP's periodic report: right after a re-join it may
    // still show the portal one, so look again before kicking
    if (station.assocTs && Date.now() / 1000 - station.assocTs < 20 && tries < 2) {
      setTimeout(() => this.recheck(portal, mac, tries + 1).catch(err =>
        log.warn(`Captive portal recheck ${mac} failed`, err.message)), 15 * 1000);
      return;
    }
    const k = await fwapc.apiCall('POST', `/control/steer/${mac}`);
    log.info(`Captive portal ${mac} still on the portal VLAN ${vlan}, kicked again: ${k.code}`);
  }
}

module.exports = CaptivePortalPlugin;
