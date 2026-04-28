#!/bin/sh

testvm run bzImage --gdb-port 1234 --nokaslr --smp 1 --net tap --network-tap tap0testvm --network-host-ip 192.168.10.1 --network-ip 192.168.10.2/24 --network-gateway 192.168.10.1 --network-dns 1.1.1.1 --autorun "$1"
