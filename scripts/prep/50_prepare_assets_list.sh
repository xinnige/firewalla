#!/bin/bash

: ${FIREWALLA_HOME:=/home/pi/firewalla}
: ${FIREWALLA_HIDDEN:=/home/pi/.firewalla}

source ${FIREWALLA_HOME}/platform/platform.sh

ASSETSD_PATH=${FIREWALLA_HIDDEN}/config/assets.d/

mkdir -p $ASSETSD_PATH
sudo chown pi:pi $ASSETSD_PATH -R

RELEASE_HASH=$(cat /etc/firewalla_release | grep HASH | cut -d: -f2 | xargs echo -n)

OS_VERSION=u$(lsb_release -r | cut -f2 | cut -d'.' -f1)

 awk '{print $0}' "${FW_PLATFORM_DIR}/all/files/assets.lst" > "${ASSETSD_PATH}/00_assets.lst"

if [ -f "${FW_PLATFORM_CUR_DIR}/files/assets.lst" ]; then
   awk '{print $0}' "${FW_PLATFORM_CUR_DIR}/files/assets.lst" >> "${ASSETSD_PATH}/00_assets.lst"
fi

if [ -f "${FW_PLATFORM_CUR_DIR}/files/${OS_VERSION}/assets.lst" ]; then
   awk '{print $0}' "${FW_PLATFORM_CUR_DIR}/files/${OS_VERSION}/assets.lst" >> "${ASSETSD_PATH}/00_assets.lst"
fi

if [ -f "${FW_PLATFORM_CUR_DIR}/files/${RELEASE_HASH}/patch.lst" ]; then
  cp "${FW_PLATFORM_CUR_DIR}/files/${RELEASE_HASH}/patch.lst" "${ASSETSD_PATH}/05_patch.lst"
fi

if [ -f "${FIREWALLA_HIDDEN}/run/assets/nmap" ]; then
  sudo cp -f "${FIREWALLA_HIDDEN}/run/assets/nmap" $(which nmap)
fi

if [ -f "/usr/share/nmap/nmap-os-db" ]; then
  sudo sed -i 's/T3(R=Y|N%DF=Y%T=3B-45%TG=40%W=403D%S=O%A=S+%F=AS%O=M5B4NW0NNT11%RD=0)/T3(R=Y%DF=Y%T=3B-45%TG=40%W=403D%S=O%A=S+%F=AS%O=M5B4NW0NNT11%RD=0)/g' /usr/share/nmap/nmap-os-db
fi

NSE_FILES="outlib.lua rand.lua tableaux.lua"

for NFILE in $NSE_FILES
do
  if [ -f "${FIREWALLA_HIDDEN}/run/assets/${NFILE}" ]; then
    if  [ ! -f "/usr/share/nmap/nselib/${NFILE}" ]; then
      sudo ln -s "${FIREWALLA_HIDDEN}/run/assets/${NFILE}" /usr/share/nmap/nselib/${NFILE}
   fi
  fi
done
