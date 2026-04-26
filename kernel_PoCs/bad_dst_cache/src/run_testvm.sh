#!/bin/sh

testvm run bzImage --smp 4 --net tap --network-tap tap0testvm --network-host-ip 192.168.10.1 --network-ip 192.168.10.2/24 --network-gateway 192.168.10.1 --network-dns 1.1.1.1 --autorun "$1"
