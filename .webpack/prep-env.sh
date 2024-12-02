#! /usr/bin/env bash


pwd
echo $NODE_PATH
sudo groupadd pi
sudo useradd -m -g pi pi
sudo mkdir -p /home/pi/logs
sudo mkdir -p ${HOME}/.firewalla
sudo ln -s /home/runner/work/firewalla/firewalla /home/pi/firewalla
sudo ln -s ${HOME}/.firewalla /home/pi/.firewalla
sudo ls -l /home/pi/firewalla
sudo ls -l /home/pi/.firewalla
sudo touch /etc/firewalla-release
sudo touch /etc/firewalla_release

arch=$(uname -m)
echo "arch $arch"
if [[ "$arch" == "x86_64" ]];then
sudo bash -c 'cat <<EOF > /etc/firewalla-release
BOARD=gold
BOARD_NAME=gold
BOARD_VENDOR=Firewalla
ARCH=x86_64
EOF'
sudo bash -c 'cat <<EOF > /etc/firewalla_release
Model: Gold
Version: 2.1223
Build Date: Thu Dec 23 17:13:17 CST 2021
HASH: da3c9a45687d8cdf75afcb5f58e27dcf
EOF'
else
sudo bash -c 'cat <<EOF > /etc/firewalla-release
BOARD=purple-se
BOARD_NAME=purple-se
BOARD_VENDOR=Firewalla
ARCH=arm64
EOF'
sudo bash -c 'cat <<EOF > /etc/firewalla_release
Model: purple-se
Version: 0.1230
Build Date: Fri Dec 30 06:52:47 UTC 2022
MD5 HASH: 4e32bb5157c8b3954107f91e4da5eaa5
EOF'
fi

sudo mkdir -p ${HOME}/.firewalla/run/device-detector-regexes
sudo mkdir -p ${HOME}/.firewalla/config/dnsmasq
sudo mkdir -p ${HOME}/.firewalla/config/assets.d
sudo mkdir -p ${HOME}/.firewalla/run/assets
sudo mkdir -p ${HOME}/.firewalla/run/scan_config
sudo mkdir -p ${HOME}/.firewalla/run/cache
sudo mkdir -p ${HOME}/.firewalla/tmp
sudo mkdir -p /home/pi/logs/
sudo mkdir -p /home/runner/.firewalla/run/assets/
sudo mkdir -p /home/pi/.firewalla/run/ovpn_profile
sudo mkdir -p /home/pi/.forever/
sudo chmod -R 777 /home/runner/work/firewalla/firewalla/
sudo chmod -R 777 /home/runner/.firewalla/
sudo chmod -R 777 /home/runner/.firewalla/run/assets/
sudo chmod -R 777 /home/pi/logs/
sudo chmod -R 777 /home/pi/
sudo mkdir -p /etc/openvpn
sudo mkdir -p /data/patch/deb/
mkdir -p ${HOME}/ovpns
mkdir -p ${HOME}/logs
mkdir -p ./coverage

sudo echo "{}" > ${HOME}/.firewalla/license
sudo echo '{"discovery":{"networkInterfaces":["eth0"]},"monitoringInterface":"eth0"}' > ${HOME}/.firewalla/config/config.test.json

npm i nyc@15.1.0
npm i -g mocha@^9.2.2
npm i jsbn@1.1.0
npm i lru-cache@5.1.1
npm i moment-timezone@0.3.1
npm i muk@0.5.3
npm i async@2.6.4

sudo apt-get install -y redis
sudo apt-get install -y ipset
sudo apt-get install -y nmap
sudo apt-get install -y wireguard

bash /home/pi/firewalla/scripts/prep/50_prepare_assets_list.sh
bash /home/pi/firewalla/scripts/update_assets.sh
echo "ls /home/pi/.firewalla/run/assets"
ls /home/pi/.firewalla/run/assets

HOME='/home/pi'
mkdir -p ${HOME}/.firewalla/run/device-detector-regexes
mkdir -p ${HOME}/.firewalla/config/dnsmasq
mkdir -p ${HOME}/.forever
mkdir -p ${HOME}/.firewalla/run/assets
mkdir -p ${HOME}/ovpns
mkdir -p ${HOME}/logs
mkdir -p ./coverage
echo "{}" > ${HOME}/.firewalla/license
sudo apt-get install redis
sudo apt-get install ipset

bash /home/pi/firewalla/scripts/prep/00_disable_power_button.sh
bash /home/pi/firewalla/scripts/prep/03_setup_fsck_schedule.sh
bash /home/pi/firewalla/scripts/prep/06_check_ovpn_conf.sh
bash /home/pi/firewalla/scripts/prep/06_setup_wg_kernlog.sh
bash /home/pi/firewalla/scripts/prep/08_update_docker_vpn_logrotate.sh
bash /home/pi/firewalla/scripts/prep/08_update_openconnect_logrotate.sh
bash /home/pi/firewalla/scripts/prep/08_update_openvpn_logrotate.sh
bash /home/pi/firewalla/scripts/prep/08_update_wgvpn_logrotate.sh
bash /home/pi/firewalla/scripts/prep/11_sshd_keys.sh
bash /home/pi/firewalla/scripts/prep/13_redis_config_maxmemory.sh
bash /home/pi/firewalla/scripts/prep/14_cleanup_tracking.sh
bash /home/pi/firewalla/scripts/prep/17_update_openssh.sh
bash /home/pi/firewalla/scripts/prep/50_prepare_assets_list.sh
redis-cli zadd rdns:domain:forcesafesearch.google.com $(date +%s) 216.239.38.120
redis-cli zadd rdns:domain:safe.duckduckgo.com  $(date +%s) 52.250.41.2
redis-cli set /home/runner/.firewalla/run/assets/speedtest.sha256 $(redis-cli get /home/pi/.firewalla/run/assets/speedtest.sha256)

## mock a local http server on 8837
# sudo apt-get install -y python3

mkdir -p ${HOME}/html/v1/config/
mkdir -p ${HOME}/html/bone/api/dv5/intel/hashset
sudo chmod -R 777 ${HOME}/html/
echo '{"tun_fwvpn":{"config":{"meta":{"type":"lan","name":"OpenVPN","uuid":"606fd400-2e25-436d-a78a-116fb8fe8183"},"enabled":false,"instance":"server","type":"server"},"state":{"mac":"02:01:11:11:11:11","mtu":null,"carrier":null,"duplex":null,"speed":null,"operstate":null,"txBytes":null,"rxBytes":null,"ip4":null,"ip4s":[],"routableSubnets":null,"ip6":null,"gateway":"","gateway6":"","dns":null,"origDns":null,"pds":null,"rtid":6,"wanConnState":null,"wanTestResult":null,"present":false}},"eth0":{"config":{"meta":{"type":"wan","name":"ISP 1","uuid":"f0b27b2a-440d-42ef-85a7-c32b9afc4d03"},"enabled":true,"dhcp6":{"numOfPDs":1,"pdSize":60},"dhcp":true,"extra":{"pingTestCount":8,"dnsTestEnabled":true,"pingTestEnabled":true,"dnsTestDomain":"github.com","pingSuccessRate":0.5,"pingTestIP":["1.1.1.1","8.8.8.8","9.9.9.9"]}},"state":{"mac":"20:6d:31:df:27:2c","mtu":"1500","carrier":"1","duplex":"full","speed":"1000","operstate":"up","txBytes":"5669405970","rxBytes":"21184241611","ip4":"192.168.196.118/24","ip4s":["192.168.196.118/24"],"routableSubnets":null,"ip6":["fdf2:aa28:7217:0:226d:31ff:fedf:272c/64","2409:871e:2700:20:226d:31ff:fedf:272c/64","fe80::226d:31ff:fedf:272c/64"],"gateway":"192.168.196.1","gateway6":"fe80::226d:31ff:fe51:8","dns":["10.8.8.8"],"origDns":["10.8.8.8"],"pds":null,"rtid":8,"wanConnState":{"ready":true,"pendingTest":false,"active":false},"wanTestResult":{"active":true,"carrier":true,"ping":true,"dns":true,"failures":[],"ts":1724840620,"wanConnState":{"ready":true,"pendingTest":false,"active":false},"http":{"testURL":"http://captive.firewalla.com","statusCode":200,"redirectURL":"","expectedCode":200,"ts":1724827548,"contentMismatch":false},"recentDownTime":1724827546},"present":true}}}' > ${HOME}/html/v1/config/interfaces
echo '{"mroute":{},"dhcp6":{"br0":{"type":"stateless","lease":86400}},"nat":{"br0-eth0":{"out":"eth0"}},"routing":{"global":{"default":{"viaIntf":"eth0"}}},"icmp":{"eth0":{"echoRequest":false},"br0":{"echoRequest":true}},"nat_passthrough":{},"dhcp":{},"version":1,"dns":{},"upnp":{},"app":{"version":"1.61","upnp":{"enable":false},"bond":[],"bondSettings":{"hash":[]},"platform":"ios"},"interface":{"bridge":{},"phy":{"eth0":{"meta":{"type":"wan","name":"ISP 1","uuid":"f0b27b2a-440d-42ef-85a7-c32b9afc4d03"},"enabled":true,"dhcp6":{"numOfPDs":1,"pdSize":60},"dhcp":true,"extra":{"pingTestCount":8,"dnsTestEnabled":true,"pingTestEnabled":true,"dnsTestDomain":"github.com","pingSuccessRate":0.5,"pingTestIP":["9.9.9.9"]}}},"openvpn":{},"vlan":{}},"mdns_reflector":{"eth0":{"enabled":false}},"sshd":{"eth0":{"enabled":true}},"ts":1723778333906}' > ${HOME}/html/v1/config/active
echo '{"updated":1724840892,"sha256sum":"67e54d0e370934f774eba51c53094626f167ffaec74bac2048bfd1b99fda59b5"}' > ${HOME}/html/bone/api/dv5/intel/hashset/metadata:bf:app.porn_bf
echo '{}' > ${HOME}/html/bone/api/dv5/intel/hashset/scan:config
python3 -m http.server -d  ${HOME}/html 8837 &
