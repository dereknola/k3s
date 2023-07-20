#!/bin/bash

server_0=$1
server_1=$2
server_2=$3

echo "
frontend k3s-frontend
    bind *:6443
    mode tcp
    option tcplog
    default_backend k3s-backend

backend k3s-backend
    mode tcp
    option tcp-check
    balance roundrobin
    default-server inter 10s downinter 5s
    server server-1 $server_0:6443 check
    server server-2 $server_1:6443 check
    server server-3 $server_2:6443 check" >> /etc/haproxy/haproxy.cfg