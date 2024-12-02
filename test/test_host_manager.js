/*    Copyright 2016-2024 Firewalla Inc.
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
'use strict'

let chai = require('chai');
const _ = require('lodash');
let expect = chai.expect;

const Host = require('../net2/Host.js');
const HostManager = require('../net2/HostManager.js');
const hostManager = new HostManager();
const log = require('../net2/logger.js')(__filename);
const rclient = require('../util/redis_manager.js').getRedisClient();


describe.skip('Test hosts', function(){
    this.timeout(10000);
    
    before((done) => (
      async() => {
        const hostkeys = await rclient.keysAsync("host:mac:*");
        for (let key of hostkeys) {
          const hostinfo = await rclient.hgetallAsync(key);
          const host = new Host(hostinfo, true);
          hostManager.hostsdb[`host:mac:${host.o.mac}`] = host
          hostManager.hosts.all.push(host);
        }
        hostManager.hosts.all = _.uniqWith(hostManager.hosts.all, (a,b) => a.o.ipv4 == b.o.ipv4 && a.o.mac == b.o.mac)

        await new Promise(resolve => setTimeout(resolve, 2000));
        done();
      })()
    );
  
    after((done) => (
      async() => {
        done();
      })()
    );
  
    it.skip('should get scan hosts', async() => {
      let tag = await hostManager.getTagMacs("7");
      let dtag = await hostManager.getTagMacs("44");
      expect(tag).to.be.eql(dtag);
    });
  
    it('should get uniq ipv4 active hosts', async() => {
      // log.debug("active hosts", hostManager.getActiveHosts().map(i => i.o.mac));
      const hosts = hostManager.getUniqActiveHosts()
      log.debug("uniq active hosts", hosts.map(i => i.o.mac));
    });

  });
  