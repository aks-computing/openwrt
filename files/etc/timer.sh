timer_running=`uci get system.@system[0].failed_login_timer_running`
if [ $timer_running -eq 0 ]
then
        (sleep 121s;uci set system.@system[0].failed_login_attempts=0 && uci set system.@system[0].failed_login_timer_running=0 && uci set system.@system[0].failed_login_timer_pid=-1 && uci commit )&
        pid=`ps | grep "sleep 121s" | grep -v grep | awk '{print $1}'`
        uci set system.@system[0].failed_login_timer_pid=$pid
        uci set system.@system[0].failed_login_timer_running=1
        uci commit
fi
if [ $timer_running -ne 0 ]
then
        pid=`uci get system.@system[0].failed_login_timer_pid`
        if [ ! `ps | grep $pid | grep -v grep` ]
        then
                (sleep 121s;uci set system.@system[0].failed_login_attempts=0 && uci set system.@system[0].failed_login_timer_running=0 && uci set system.@system[0].failed_login_timer_pid=-1 && uci commit )&
                pid=`ps | grep "sleep 121s" | grep -v grep | awk '{print $1}'`
                uci set system.@system[0].failed_login_timer_pid=$pid
                uci set system.@system[0].failed_login_timer_running=1
                uci commit
        fi
fi

