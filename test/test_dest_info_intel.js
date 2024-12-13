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

const Alarm = require('../alarm/Alarm.js');
const log = require('../net2/logger.js')(__filename, 'info');
const DestInfoIntel = require('../intel/DestInfoIntel.js');
const destInfoIntel = new DestInfoIntel();

const data = {"p.device.id":"A:BB:CC:DD:EE:FF","p.device.ip":"172.16.1.144","p.protocol":"tcp","p.dest.name":"www.nintendo.co.jp","p.dest.ip":"23.5.1.243","p.dest.id":"www.nintendo.co.jp",
    "p.dest.port":443,"p.intf.id":"0000000","p.dtag.ids":["1"],"p.device.mac":"A:BB:CC:DD:EE:FF", "p.dest.category":"av"};

describe('Test localization', function(){
    this.timeout(30000);

    it('should enrich alarm domain info', async() => {
        const alarm1 = new Alarm.GameAlarm(Date.now()/1000, 'MacBook Air', 'www.nintendo.co.jp', data);
        await destInfoIntel.enrichAlarm(alarm1);
        expect(alarm1["p.dest.name.suffix"]).to.be.equal("nintendo.co.jp");
    });
});

