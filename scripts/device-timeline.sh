#!/usr/bin/env bash

# device-timeline.sh
# Usage:
#   ./device-timeline.sh -h
#   ./device-timeline.sh -m "6C:1F:F7:23:39:CB"

# Parse arguments
device_mac=""
hours_filter=""
force_copy=false

while getopts "hm:t:f" opt; do
    case $opt in
        h)
            echo "Usage: $0 -m mac [-t hours]"
            echo "  -m: Device MAC address (required)"
            echo "  -f: Force copy AP logs even if they are recent"
            echo "  -t: Show only events from last N hours (optional)"
            echo "  -h: Show this help message"
            exit 0
            ;;
        m)
            device_mac="$OPTARG"
            ;;
        t)
            hours_filter="$OPTARG"
            ;;
        f)
            force_copy=true
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            echo "Usage: $0 -m mac [-t hours]"
            exit 1
            ;;
    esac
done

if [ -z "$device_mac" ]; then
    echo "Error: MAC address is required"
    echo "Usage: $0 -m mac [-t hours]"
    exit 1
fi

device_mac=$(echo "$device_mac" | tr '[:lower:]' '[:upper:]')

# Global mapping of AP UID to name
declare -A ap_uid_to_name

echo "Device MAC: $device_mac"
echo "Getting device timeline..."


########################################################
# Copy AP syslog and ap.log to box with throttling
########################################################
function mapping_ap_uid_to_name() {
    data=`curl -s localhost:8841/v1/status/ap | jq -r '.info | to_entries[] | "\(.key),\(.value.name)"'`
    for line in $data
    do
        read uid name< <(echo "$line"| awk -F"," '{print $1" "$2}')
        ap_uid_to_name["$uid"]="$name"
    done
}

########################################################
# Copy AP syslog and ap.log to box with throttling
########################################################
function copy_ap_log() {
    # Check if sshpass is installed
    if ! command -v sshpass &> /dev/null; then
        echo "Warning: sshpass is not installed. Skipping AP log reading."
        echo "Install with: sudo apt-get install sshpass"
        return 1
    fi

    # Create lock file for throttling (10 minutes = 600 seconds)
    local lock_file="/tmp/log/ap/.copy_ap_log.lock"
    if [ "$force_copy" = true ]; then
        rm -f "$lock_file"
    fi
    local throttle_seconds=600

    # Check if we should skip due to throttling (unless force is enabled)
    if [ "$force_copy" != "true" ] && [ -f "$lock_file" ]; then
        local last_run=$(cat "$lock_file" 2>/dev/null)
        local current_time=$(date +%s)
        local time_diff=$((current_time - last_run))

        if [ "$time_diff" -lt "$throttle_seconds" ]; then
            local remaining=$((throttle_seconds - time_diff))
            echo "AP logs last copied ${time_diff}s ago, skip. (${remaining}s remaining)"
            mapping_ap_uid_to_name
            return 0
        fi
    fi

    # Update lock file with current timestamp
    echo "$(date +%s)" > "$lock_file"

    data=`curl -s localhost:8841/v1/status/ap | jq -r '.info | to_entries[] | "\(.key),\(.value.licenseUuid),\(.value.name)"'`
    config=`curl -s localhost:8841/v1/config/active | jq -r '.assets | to_entries[] | "\(.key),\(.value.publicKey),\(.value.sysConfig.seq)"'`
    wgdata=`sudo wg show wg_ap dump`

    for line in $data
    do
        read uid lid name< <(echo "$line"| awk -F"," '{print $1" "$2" "$3}')
        # Populate global mapping of UID to name
        ap_uid_to_name["$uid"]="$name"
        seq=$(echo "$config" | grep $uid | awk -F"," '{print $3}')
        pass=$(echo -n "firewalla:$seq:$lid:$uid" | shasum -a 256 | cut -f1 -d" " | xxd -r -p | base64 | cut -c 6-15)
        pubkey=$(echo "$config" | grep $uid | awk -F"," '{print $2}')
        ipaddr=$(echo "$wgdata" | grep $pubkey | awk '{print $4}' | cut -f1 -d "/")
        mkdir -p /tmp/log/ap

        # Check if we need to copy by comparing file timestamps
        local local_syslog="/tmp/log/ap/$uid.syslog"
        local local_aplog="/tmp/log/ap/$uid.ap.log"
        local needs_copy=false

        # Force copy if flag is set, otherwise check file age
        if [ "$force_copy" = "true" ]; then
            needs_copy=true
        elif [ ! -f "$local_syslog" ] || [ ! -f "$local_aplog" ]; then
            needs_copy=true
        else
            # Check if local files are older than 5 minutes (300 seconds)
            local local_age=$(($(date +%s) - $(stat -c %Y "$local_syslog" 2>/dev/null || echo 0)))
            if [ "$local_age" -gt 300 ]; then
                needs_copy=true
            fi
        fi

        if [ "$needs_copy" = true ]; then
            echo "Copying logs for AP $uid ($name)..."
            # Copy with error handling
            if sshpass -p $pass scp -P 8842 -o StrictHostkeyChecking=no -o HostKeyAlgorithms=+ssh-rsa -o ConnectTimeout=15 root@$ipaddr:/root/syslog "$local_syslog" 2>/dev/null; then
                echo "  ✓ syslog copied"
            else
                echo "  ✗ Failed to copy syslog for $uid"
                rm -f /tmp/log/ap/.copy_ap_log.lock
            fi

            if sshpass -p $pass scp -P 8842 -o StrictHostkeyChecking=no -o HostKeyAlgorithms=+ssh-rsa -o ConnectTimeout=15 root@$ipaddr:/root/syslog.old "${local_syslog}.old" 2>/dev/null; then
                echo "  ✓ syslog.old copied"
            fi


            if sshpass -p $pass scp -P 8842 -o StrictHostkeyChecking=no -o HostKeyAlgorithms=+ssh-rsa -o ConnectTimeout=15 root@$ipaddr:/var/log/ap.log "$local_aplog" 2>/dev/null; then
                echo "  ✓ ap.log copied"
            else
                echo "  ✗ Failed to copy ap.log for $uid"
                rm -f /tmp/log/ap/.copy_ap_log.lock
            fi


            if sshpass -p $pass scp -P 8842 -o StrictHostkeyChecking=no -o HostKeyAlgorithms=+ssh-rsa -o ConnectTimeout=15 root@$ipaddr:/var/log/ap.log.1 "${local_aplog}.1" 2>/dev/null; then
                echo "  ✓ ap.log.1 copied"
            fi
        else
            echo "Skipping AP $uid ($name) - logs are recent"
        fi
    done
}

copy_ap_log

########################################################
# AP events
########################################################
# {"ap":"20:6D:31:61:00:24","band":"5g","bssid":"32:6D:31:61:00:27","channel":36,"intf":"ath14","mac":"42:71:A1:E0:C0:DD","mesh":false,"reason":null,"rssi":-37,"ssid":"Test_710GF_mlo","system_event":"station_connect","ts":1760093674529}
# {"ap":"20:6D:31:61:00:24","band":"2g","bssid":"2A:6D:31:61:00:26","channel":5,"intf":"ath02","mac":"42:71:A1:E0:C0:DD","mesh":false,"reason":null,"rssi":-33,"ssid":"Test_710GF_mlo","system_event":"station_disconnect","ts":1760093674479}
ap_events_raw=$(curl -s -H 'Content-Type: application/json' -XGET "http://127.0.0.1:8841/v1/event_history/$device_mac"| jq -r '.[]')
ap_events=$(echo "$ap_events_raw" | jq -r '[.ts, "[event] Device \(.mac) \(.system_event) on SSID \(.ssid) on AP \(.ap), band: \(.band), channel: \(.channel), intf: \(.intf), rssi: \(.rssi), bssid: \(.bssid)"] | @tsv')

########################################################
# AP log
########################################################
# grep -H -i "3E:BC:99:52:15:1A" /tmp/log/ap/*.syslog | grep hostapd
# /tmp/log/ap/20:6D:31:61:00:24.syslog:Fri Oct 10 12:57:58 2025 daemon.info hostapd: ath13: STA 3e:bc:99:52:15:1a IEEE 802.11: authenticated
# /tmp/log/ap/20:6D:31:61:00:24.syslog:Fri Oct 10 12:57:58 2025 daemon.info hostapd: ath13: STA 3e:bc:99:52:15:1a IEEE 802.11: associated (aid 1)
ap_log_raw=$(grep -H -i "$device_mac" /tmp/log/ap/*.syslog 2>/dev/null)

# Parse ap_log_raw to format: (timestamp_ms, log_line)
ap_log=$(echo "$ap_log_raw" | while IFS= read -r line; do
    if [ -z "$line" ]; then
        continue
    fi
    # Extract filename and log content (format: filename.log:log_line)
    filename=$(echo "$line" | sed 's/log:.*$//')
    log_content=$(echo "$line" | sed 's/^.*log://')

    # Extract timestamp from log content (first 5 fields: "Fri Oct 10 12:57:58 2025")
    timestamp=$(echo "$log_content" | awk '{print $1, $2, $3, $4, $5}')
    data=$(echo "$log_content" | cut -d' ' -f8-)

    # Extract AP UID from filename (remove path and .syslog extension)
    ap_uid=$(basename "$filename" .sys)

    ts_sec=$(date -d "$timestamp" "+%s" 2>/dev/null)
    if [ -n "$ts_sec" ]; then
        ts_ms=$((ts_sec * 1000))
        # Output: timestamp_ms<tab>original_line with AP info
        printf "%s\t%s\n" "$ts_ms" "[AP $ap_uid] $data"
    fi
done)

########################################################
# DHCP leases
########################################################
# cat /home/pi/.router/run/dhcp/dnsmasq.leases
# 1760234169 68:da:73:ac:11:07 192.168.20.144 XinniGes-Air 01:68:da:73:ac:11:07
# 1760238702 3e:bc:99:52:15:1a 10.93.177.21 iPhone 01:3e:bc:99:52:15:1a
dhcp_leases_raw=$(cat /home/pi/.router/run/dhcp/dnsmasq.leases | grep -i "$device_mac")
dhcp_leases=$(echo "$dhcp_leases_raw" | while IFS= read -r line; do
    if [ -z "$line" ]; then
        continue
    fi
    # Extract timestamp (first field) and rest of line
    timestamp=$(echo "$line" | awk '{print $1}')
    data=$(echo "$line" | cut -d' ' -f2-)

    # Convert timestamp from seconds to milliseconds
    ts_ms=$((timestamp * 1000))
    # Output: timestamp_ms<tab>original_line
    printf "%s\t%s\n" "$ts_ms" "[dhcp] $data will expire at $(date -d "@$timestamp" "+%Y-%m-%d %H:%M:%S %Z")"
done)

########################################################
# Captive portal flows
########################################################
#  score uses .ts field which is in seconds (e.g., 1761793385.077302)
# flow:http:outbound:$device_mac
## {"ts":1761793385.077302,"uid":"Cc9AML3zTU7hb4F757","id.orig_h":"192.168.201.222","id.orig_p":58441,"id.resp_h":"17.253.9.132","id.resp_p":80,"trans_depth":1,"method":"GET","host":"captive.apple.com","uri":"/hotspot-detect.html","version":"1.1","user_agent":"CaptiveNetworkSupport-491.100.3 wispr","request_body_len":0,"response_body_len":69,"status_code":200,"status_msg":"OK","tags":[],"resp_fuids":["Fenq0j1ulRbK7BVP5e"],"resp_mime_types":["text/html"]}
## {"ts":1761793385.077302,"uid":"Cc9AML3zTU7hb4F757","id.orig_h":"192.168.201.222","id.orig_p":58441,"id.resp_h":"17.253.9.132","id.resp_p":80,"trans_depth":1,"method":"GET","host":"captive.apple.com","uri":"/hotspot-detect.html","version":"1.1","user_agent":"CaptiveNetworkSupport-491.100.3 wispr","request_body_len":0,"response_body_len":0,"status_code":200,"status_msg":"OK","tags":[]}
# flow:conn:in:$device_mac
## {"ts":1761793384.97,"_ts":1761793395.261,"sh":"192.168.201.222","dh":"17.253.9.132","ob":240,"rb":459,"ct":1,"fd":"in","lh":"192.168.201.222","intf":"d65b9384","du":0.41,"pr":"tcp","uids":["Cc9AML3zTU7hb4F757"],"ltype":"mac","oIntf":"0969713f","af":{"captive.apple.com":{"proto":"http","ip":"17.253.9.132"}},"dTags":["1"],"userTags":["20"],"tags":["19"],"dstTags":{},"sp":[58441],"dp":80}
cutoff_ts=""
if [ -n "$hours_filter" ]; then
    cutoff_ts=$(($(date +%s) - ($hours_filter * 3600)))
    captive_portal_flows_http_raw=$(redis-cli zrangebyscore flow:http:outbound:$device_mac $cutoff_ts +inf | fgrep "captive.apple.com" | tail -n 1000 2>/dev/null | jq -c)
    captive_portal_flows_raw=$(redis-cli zrangebyscore flow:conn:in:$device_mac $cutoff_ts +inf| fgrep "captive.apple.com" | tail -n 1000 2>/dev/null | jq -c)
else
    # Default to last 20 items if no hours filter
    captive_portal_flows_http_raw=$(redis-cli zrevrange flow:http:outbound:$device_mac 0 1000 2>/dev/null | fgrep "captive.apple.com" 2>/dev/null | jq -c)
    captive_portal_flows_raw=$(redis-cli zrevrange flow:conn:in:$device_mac 0 1000 2>/dev/null | fgrep "captive.apple.com" | tail -n 1000 2>/dev/null | jq -c)
fi

captive_portal_flows_http=$(echo "$captive_portal_flows_http_raw" | jq -s -r --arg mac "$device_mac" '.[] | select(. != null) | [(.ts | tonumber | . * 1000 | floor), "[http] Device \($mac) \(."id.orig_h") \(.method) \(.host) \(."id.resp_h") \(.status_code) \(.status_msg)"] | @tsv')
captive_portal_flows=$(echo "$captive_portal_flows_raw" | jq -s -r '.[] | select(. != null) | [(.ts | tonumber | . * 1000 | floor), "[captive] Device \(.sh) access captive.apple.com \(.dh) \(.pr):\(.dp) via \(.intf)"] | @tsv')

########################################################
# DHCP events
########################################################
# {"action":"old","mac":"aa:65:46:54:f5:42","ip":"10.228.16.55","hostname":"iPhone","options":"","expires":"1761292875","clientid":"01:aa:65:46:54:f5:42","interface":"br5","ts":"1761206607824"}
# {"action":"old","mac":"aa:65:46:54:f5:42","ip":"10.228.16.55","hostname":"iPhone","options":"","expires":"1761292875","clientid":"01:aa:65:46:54:f5:42","interface":"br5","ts":"1761206496219"}
# {"action":"old","mac":"aa:65:46:54:f5:42","ip":"10.228.16.55","hostname":"iPhone","options":"1,121,3,6,15,108,114,119,252","expires":"1761292875","clientid":"01:aa:65:46:54:f5:42","interface":"br5","ts":"1761206475201"}
# {"action":"old","mac":"aa:65:46:54:f5:42","ip":"10.228.16.55","hostname":"","options":"","expires":"1761270941","clientid":"01:aa:65:46:54:f5:42","interface":"br5","ts":"1761206428199"}
# {"action":"old","mac":"aa:65:46:54:f5:42","ip":"10.228.16.55","hostname":"","options":"","expires":"1761270941","clientid":"01:aa:65:46:54:f5:42","interface":"br5","ts":"1761206307795"}
device_mac_lower=$(echo "$device_mac" | tr '[:upper:]' '[:lower:]')
# Calculate cutoff timestamp for DHCP events (Redis score uses .ts field which is in milliseconds)
# Calculate cutoff time if hours filter is specified
cutoff_ts_ms=""
if [ -n "$hours_filter" ]; then
    cutoff_ts_ms=$((($(date +%s) - ($hours_filter * 3600)) * 1000))
    dhcp_events_raw=$(redis-cli zrangebyscore dnsmasq.dhcp.event:$device_mac_lower $cutoff_ts_ms +inf LIMIT 0 1000 2>/dev/null | jq -c)
else
    # Default to last 20 items if no hours filter
    dhcp_events_raw=$(redis-cli zrevrange dnsmasq.dhcp.event:$device_mac_lower 0 20 | jq -c)
fi
local_tz=$(date +%Z)
dhcp_events=$(echo "$dhcp_events_raw" | jq -r --arg tz "$local_tz" '[.ts, "[dhcp] Device \(.mac) \(.ip) \(.hostname) lease on interface \(.interface) with options \"\(.options)\" expires at " + (.expires | tonumber | strftime("%Y-%m-%d %H:%M:%S")) + " " + $tz] | @tsv')

########################################################
# Radius authentication and accounting log
########################################################
# search /home/pi/.forever/freeradius/radacct
# search /home/pi/.forever/freeradius/radauth
# change $device_mac : to -
device_mac_dash=$(echo "$device_mac" | sed 's/:/-/g')
# {"ts":"1760600851","event_ts":"1760600851","user_name":"lizzy","acct_status_type":"Start","acct_session_id":"9E19E51EEB7B0CCC","acct_unique_session_id":"735078701a1e8e872c8f8f4724e9b7e0","acc_multi_session_id":"A3AF2D3ABEBE9C12","nas_port_type":"Wireless-802.11","nas_port":"1","nas_ip_address":"10.89.112.141","framed_ip_address":"","calling_station_id":"AA-65-46-54-F5-42","called_station_ssid":"Test_710GF_2_5g","called_station_id":"2E-6D-31-61-00-27"}
# {"ts":"1760607668","event_ts":"1760607668","user_name":"lizzy","acct_status_type":"Stop","acct_session_id":"9E19E51EEB7B0CCC","acct_unique_session_id":"735078701a1e8e872c8f8f4724e9b7e0","acc_multi_session_id":"A3AF2D3ABEBE9C12","nas_port_type":"Wireless-802.11","nas_port":"1","nas_ip_address":"10.89.112.141","framed_ip_address":"","calling_station_id":"AA-65-46-54-F5-42","called_station_ssid":"Test_710GF_2_5g","called_station_id":"2E-6D-31-61-00-27","acct_session_time":"6817","acct_input_octets":"1968003","acct_output_octets":"1097402","acct_input_packets":"14913","acct_output_packets":"115451","acct_term_cause":""}
radius_acct_str=$(grep -h -i "$device_mac_dash" /home/pi/.forever/freeradius/radacct/*/* 2>/dev/null)
radius_acct=$(echo "$radius_acct_str" | jq -r '[.ts + "000", "[radius] Device \(.calling_station_id | gsub("-"; ":")) logged in as \(.user_name) \(.acct_status_type | ascii_downcase) accounting on SSID \(.called_station_ssid) via AP \(.called_station_id | gsub("-"; ":")) \(.acct_term_cause)"] | @tsv')

# {"ts":"1760667128","event_ts":"1760667128","result":"Access-Reject","realm":"","user_group":"","user_name":"edison","nas_ip":"10.11.12.75","nas_id":"","calling_station_id":"9E-73-94-08-AD-4E","called_station_id":"20-6D-31-71-01-8F","called_station_ssid":"SGoldX","reply_message":"","reason":"eap_peap: The users session was previously rejected: returning reject (again.)", "root_reason":"mschap: FAILED: No NT-Password.  Cannot perform authentication"}
# {"ts":"1761047559","event_ts":"1761047559","result":"Access-Reject","realm":"","user_group":"","user_name":"Jasmine","nas_ip":"10.11.12.95","nas_id":"","calling_station_id":"50-BC-96-08-40-08","called_station_id":"20-6D-31-71-01-17","called_station_ssid":"SGoldX","reply_message":"","reason":"eap_peap: The users session was previously rejected: returning reject (again.)", "root_reason":"mschap: MS-CHAP2-Response is incorrect"}
# {"ts":"1761105209","event_ts":"1761105209","result":"Access-Accept","realm":"","user_group":"","user_name":"lizzy","nas_ip":"10.89.112.141","nas_id":"","calling_station_id":"AA-65-46-54-F5-42","called_station_id":"2E-6D-31-61-00-27","called_station_ssid":"Test_710GF_2_5g","reply_message":"Hello, lizzy. Device AA-65-46-54-F5-42 is connected to 2E-6D-31-61-00-27.","reason":"", "root_reason":""}
radius_auth_str=$(grep -h -i "$device_mac_dash" /home/pi/.forever/freeradius/radauth/*/* 2>/dev/null)
radius_auth=$(echo "$radius_auth_str" | jq -r '[.ts + "000", "[radius] Device \(.calling_station_id | gsub("-"; ":")) \(.result | ascii_downcase) as \(.user_name) on SSID \(.called_station_ssid) via AP \(.called_station_id | gsub("-"; ":")) reason: \(.root_reason)"] | @tsv')

########################################################
# Merge and sort by timestamp (ascending order
# stable sort to preserve original order for same timestamps)
########################################################
timeline=$(printf "%s\n%s\n%s\n%s\n" "$ap_events" "$ap_log" "$dhcp_leases" "$dhcp_events" "$radius_auth" "$radius_acct" "$captive_portal_flows_http" "$captive_portal_flows"| sort -s -t$'\t' -k1 -n)

echo ""
echo "=== Device Timeline (sorted by timestamp) ==="

# Calculate cutoff time if hours filter is specified
cutoff_ts_ms=""
if [ -n "$hours_filter" ]; then
    cutoff_ts_ms=$((($(date +%s) - ($hours_filter * 3600)) * 1000))
fi

echo "$timeline" | while IFS=$'\t' read -r ts_ms data; do
    if [ -z "$ts_ms" ]; then
        continue
    fi

    # Extract only numeric timestamp (remove any tabs, whitespace, or trailing non-numeric characters)
    ts_ms=$(echo "$ts_ms" | sed 's/\t.*$//; s/[^0-9].*$//; s/[[:space:]]//g')
    
    # Skip if ts_ms is not a valid number
    if [ -z "$ts_ms" ] || ! [[ "$ts_ms" =~ ^[0-9]+$ ]]; then
        continue
    fi

    # Apply hours filter if specified
    if [ -n "$cutoff_ts_ms" ]; then
        if [ "$ts_ms" -lt "$cutoff_ts_ms" ]; then
            continue
        fi
    fi

    # Convert milliseconds to seconds
    ts_sec=$((ts_ms / 1000))
    # Convert to readable date format with timezone
    date_str=$(date -d "@$ts_sec" "+%Y-%m-%d %H:%M:%S %Z" 2>/dev/null)
    if [ -n "$date_str" ]; then
        # Replace any AP UID in the data line with AP name
        enhanced_data="$data"
        for uid in "${!ap_uid_to_name[@]}"; do
            if [[ "$enhanced_data" == *"$uid"* ]]; then
                ap_name="${ap_uid_to_name[$uid]}"
                if [ -n "$ap_name" ]; then
                    enhanced_data="${enhanced_data//$uid/$uid ($ap_name)}"
                fi
            fi
        done
        printf "%s\t%s\n" "$date_str" "$enhanced_data"
    fi
done
