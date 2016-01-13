#!/bin/sh

mac_increment () {
        mac_str=$1
        #echo $mac_str ${#mac_str}

        arr=$(echo $mac_str | tr ":" "\n")
        #echo $arr ${#arr}

        y=""
        for x in $arr
        do
                y=$y$x
        done
        y=0x$y
        #echo $y ${#y}

        mac_incr=`printf "%X\n" $(( $y + 1 ))`
        #echo $mac_incr ${#mac_incr}

        if [ ${#mac_incr} -ne 12 ]
        then
                x=$(( 12 - ${#mac_incr} ))
                while [ $x -ne 0 ]
                do
                        mac_incr=0$mac_incr
                        x=$(( $x - 1 ))
                done
        fi

        #echo $mac_incr ${#mac_incr}
        mac_incr_str=`echo $mac_incr | cut -c1-2`":"`echo $mac_incr | cut -c3-4`":"`echo $mac_incr | cut -c5-6`":"`echo $mac_incr | cut -c7-8`":"`echo $mac_incr | cut -c9-10`":"`echo $mac_incr | cut -c11-12`
        #echo $mac_incr_str ${#mac_incr_str}
        eval $2=$mac_incr_str
}
# if wan macaddr is not present
if ! uci -q get network.wan.macaddr
then
        mac_increment $(ifconfig br-lan|grep HWaddr|awk '{print $5}') new_mac
        #mac_increment $(uci get network.lan.macaddr) new_mac
        uci set network.wan.macaddr=$new_mac
        uci commit
fi

# setting Wi-Fi SSID
ssid=PowerBrickGateway$(ifconfig br-lan|grep HWaddr|awk '{print $5}'|cut -c9-19)
uci set wireless.@wifi-iface[0].ssid=$ssid
uci commit

# set option driver for 4G module
echo '05c6 9025 ff' > /sys/bus/usb-serial/drivers/option1/new_id

# check whether the changes are required
if  uci -q get network.wan6
then

	# check whether any module is inserted
	if [ -f /sys/bus/usb/drivers/usb/1-1.2/idProduct ]
	then
		# check for 4G module vendor=05c6 product=9025 is Qualcomm, Inc. Qualcomm HSUSB Device - 4G module FORGE SLM630
		if [ `cat /sys/bus/usb/drivers/usb/1-1.2/idProduct` -eq 9025 ]
		then
		        uci set firewall.@zone[1].network='wan 4g_wan6'
		        uci set system.@system[0].model=GW4G00
		        uci rename mwan3.wan6=4g_wan6
		        uci set mwan3.wan6_m1_w2.interface=4g_wan6
		        uci set mwan3.wan6_m2_w2.interface=4g_wan6
		        uci set network.wan6.device='/dev/ttyUSB2'
		        uci rename network.wan6=4g_wan6
		        uci commit
		        /etc/init.d/network reload
		        sleep 5s
		        /usr/sbin/mwan3 restart
		        sleep 5s
		# otherwise check for 3G module vendor=12d1 product=1573 is Huawei Technologies Co., Ltd. MU609
		elif [ `cat /sys/bus/usb/drivers/usb/1-1.2/idProduct` -eq 1573 ]
		then
			uci set system.@system[0].model=GW3G00
			uci commit
		fi
	else
		uci set system.@system[0].model=GW00
		uci commit
	fi
fi

# set IMEI and APN for wwan
if [ `cat /sys/bus/usb/drivers/usb/1-1.2/idProduct` -eq 9025 ]
then
        uci set network.4g_wan6.imei=`gcom -d /dev/ttyUSB1 info | grep "IMEI and Serial Number:" | cut -d " " -f5`
	oper=`gcom -d /dev/ttyUSB1 | grep "Registered on Home network: " | cut -d "\"" -f2`
	if  echo $oper | grep -iq "telecom"
	then
		uci set network.4g_wan6.apn='direct.telecom.co.nz'
	elif echo $oper | grep -iq "spark"
	then
		uci set network.4g_wan6.apn='direct.telecom.co.nz'
	elif echo $oper | grep -iq "vodafone"
	then
		uci set network.4g_wan6.apn='internet'
	elif echo $oper | grep -iq "2degrees"
	then
		uci set network.4g_wan6.apn='direct'
	else
		uci set network.4g_wan6.apn='internet'
	fi
        uci commit
elif [ `cat /sys/bus/usb/drivers/usb/1-1.2/idProduct` -eq 1573 ]
then
        uci set network.wan6.imei=`gcom info | grep "IMEI and Serial Number:" | cut -d " " -f5`
	oper=`gcom | grep "Registered on Home network: " | cut -d "\"" -f2`
	if echo $oper | grep -iq "telecom"
	then
		uci set network.wan6.apn='direct.telecom.co.nz'
        elif echo $oper | grep -iq "spark"
        then
                uci set network.wan6.apn='direct.telecom.co.nz'
	elif echo $oper | grep -iq "vodafone"
	then
		uci set network.wan6.apn='internet'
	elif echo $oper | grep -iq "2degrees" 
	then
		uci set network.wan6.apn='direct'
	else
		uci set network.wan6.apn='internet'
	fi
        uci commit
fi

/etc/init.d/network reload
echo "config csvipalarm
	option exec '/sbin/csvipalarmservice restart'
">> /etc/config/ucitrack
/sbin/csvipalarmservice restart
exit 0
