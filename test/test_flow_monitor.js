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
let expect = chai.expect;

let log = require('../net2/logger.js')(__filename, 'info');

const Host = require('../net2/Host.js');
const FlowMonitor = require('../monitor/FlowMonitor.js');
const { flow } = require('lodash');
const flowMonitor = new FlowMonitor(1200, 9600);

const flows=[
    {"ts":1729579923.26,"_ts":1729579932.49,"sh":"172.16.102.144","dh":"23.42.204.241","ob":4066,"rb":3670,"ct":1,"fd":"in","lh":"192.168.196.144","intf":"ed80e488","du":0.59,"pr":"tcp","uids":["CQScD63ab9zkqc6Yvi"],"ltype":"mac","oIntf":"f334b467","af":{"cdn.accounts.nintendo.com":{"proto":"ssl","ip":"23.42.204.241"}},"apid":39,"sp":[61058],"dp":443,"dTags":["1"],"userTags":["3"],"tags":["2"],intel:{c:"games"}},
    {"ts":1729579918.79,"_ts":1729579932.38,"sh":"172.16.102.144","dh":"151.101.129.55","ob":7434,"rb":181268,"ct":1,"fd":"in","lh":"192.168.196.144","intf":"ed80e488","du":5.06,"pr":"tcp","uids":["CBGB6TZmPyGA0uONd"],"ltype":"mac","oIntf":"f334b467","af":{"www.nintendo.com":{"proto":"ssl","ip":"151.101.129.55"}},"apid":41,"sp":[61031],"dp":443,"dTags":["1"],"userTags":["3"],"tags":["2"],intel:{c:"games"}},
    {"ts":1729579922.16,"_ts":1729579932.36,"sh":"172.16.102.144","dh":"72.246.244.202","ob":5596,"rb":92820,"ct":1,"fd":"in","lh":"192.168.196.144","intf":"ed80e488","du":1.69,"pr":"tcp","uids":["CxODT720RI6z1MrA9d"],"ltype":"mac","oIntf":"f334b467","af":{"accounts.nintendo.com":{"proto":"ssl","ip":"72.246.244.202"}},"apid":39,"sp":[61053],"dp":443,"dTags":["1"],"userTags":["3"],"tags":["2"],intel:{c:"games"}},
]
const hosto = {"dnsmasq.dhcp.leaseName":"Macbook-Air","intf":"ed80e488-c864-4634-b644-b5e9e56ee659","detect":"{\"type\":\"desktop\",\"bonjour\":{\"type\":\"desktop\",\"brand\":\"Apple\",\"name\":\"XinniGe’s MacBook Air\",\"model\":\"Mac14,2\"},\"brand\":\"Apple\",\"name\":\"MacBook Air\",\"model\":\"Mac14,2\"}","pname":"(?) Apple Mac14,2","mac":"00:DA:AB:AC:11:07","dhcpName":"Macbook-Air","ipv6Addr":"[\"fe80::1c3c:40de:abcd:2f6f\",\"fdc6:b2ae:ef24:0:abcd:abcd:94c3:6445\"]","ipv4":"172.16.102.144","localDomain":"macbook.air","intf_uuid":"ed80e488-c864-4634-b644-b5e9e56ee659","firstFoundTimestamp":"1723716560.477","lastFrom":"macHeartbeat","ipv4Addr":"172.16.102.144","macVendor":"Apple Inc.","intf_mac":"20:6d:31:ab:cd:40","bonjourName":"MacBook Air"};
const profile = {"duMin": 3, "rbMin": 30000, "ctMin": 3, "cooldown": 900 };

describe('Test flow monitor', function(){
    this.timeout(30000);

    before(async() => {
    });
  
    after(async() => {
    });

    it('Should check flow intel in class', async()=> {
        expect(flowMonitor.isFlowIntelInClass({c:"games"}, "games")).to.be.true;
    });

    it('Should check alarm threshold', async()=> {
        expect(flowMonitor.checkAlarmThreshold(flows[0], 'games', {game: profile})).to.be.false;
        log.debug("recordedFlows", flowMonitor.recordedFlows.keys());
        expect(flowMonitor.checkAlarmThreshold(flows[1], 'games', {game: profile})).to.be.true;
        log.debug("recordedFlows", flowMonitor.recordedFlows.values());
        expect(flowMonitor.checkAlarmThreshold(flows[2], 'games', {game: profile})).to.be.false;
    });
});