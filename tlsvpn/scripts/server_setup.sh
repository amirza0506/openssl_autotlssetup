#!/bin/bash

ip tuntap add dev tun0 mode tun
ip addr add 10.0.0.1/24 dev tun0
ip link set tun0 up

echo 1 > /proc/sys/net/ipv4/ip_forward
