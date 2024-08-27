#! /usr/bin/env bash


pwd
echo $NODE_PATH
sudo mkdir -p /home/pi
sudo ln -s /home/runner/work/firewalla/firewalla /home/pi/firewalla
sudo ls -l /home/pi/firewalla

npm i nyc@15.1.0
npm i mocha@2.5.3
npm i jsbn@1.1.0
npm i lru-cache@5.1.1
npm i moment-timezone@0.3.1
npm i muk@0.5.3
npm i async@2.6.4

sudo touch /etc/firewalla-release
sudo bash -c 'cat <<EOF > /etc/firewalla-release
BOARD=gold
BOARD_NAME=gold
BOARD_VENDOR=Firewalla
ARCH=x86_64
EOF'

sudo touch /etc/firewalla_release
sudo bash -c 'cat <<EOF > /etc/firewalla_release
Model: Gold
Version: 2.1223
Build Date: Thu Dec 23 17:13:17 CST 2021
HASH: da3c9a45687d8cdf75afcb5f58e27dcf
EOF'

mkdir -p ${HOME}/.firewalla/run/device-detector-regexes
mkdir -p ${HOME}/.firewalla/config/dnsmasq
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