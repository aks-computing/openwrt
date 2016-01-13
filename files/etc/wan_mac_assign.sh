#!/bin/sh
if [ $# -eq 1 ]
then
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
        uci set network.wan.macaddr=$mac_incr_str
        uci set network.lan.macaddr=$1
        uci commit

#       logger -t proto.lua -p notice `ifconfig eth0.2| grep -i HWaddr`
#       logger -t proto.lua -p notice `ifconfig br-lan| grep -i HWaddr`
        ifdown wan
        ifconfig eth0.2 hw ether $mac_incr_str
        sleep 1s
        ifup wan
#       logger -t proto.lua -p notice `ifconfig br-lan| grep -i HWaddr`
#       logger -t proto.lua -p notice `ifconfig eth0.2| grep -i HWaddr`
fi


