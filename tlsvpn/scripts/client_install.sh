#!/bin/bash

ip tuntap add dev tun0 mode tun
ip addr add 10.0.0.2/24 dev tun0
ip link set tun0 up

ip route add default via 10.0.0.1 dev tun0
