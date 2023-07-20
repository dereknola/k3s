#!/bin/bash

state=$1
vip=$2

if [ "$state" = "MASTER" ]; then
    lb_priority=200
else
    lb_priority=100
fi

echo "vrrp_script chk_haproxy {
    script 'killall -0 haproxy' # faster than pidof
    interval 2
}

vrrp_instance haproxy-vip {
   interface eth1
    state $state
    priority $lb_priority

    virtual_router_id 51

    virtual_ipaddress {
        $vip/24
    }

    track_script {
        chk_haproxy
    }
}" >> /etc/keepalived/keepalived.conf
