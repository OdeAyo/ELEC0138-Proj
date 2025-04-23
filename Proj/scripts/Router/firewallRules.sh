#!/bin/bash

iptables -F

iptables -A INPUT -p tcp --tcp-flags RST RST -m ttl --ttl-lt 128 -j DROP
iptables -A INPUT -p tcp --tcp-flags RST RST -m conntrack --ctstate NEW,INVALID -j DROP
iptables -A INPUT -p tcp --tcp-flags RST RST -m recent --name RST --set
iptables -A INPUT -p tcp --tcp-flags RST RST -m recent --name RST --update --seconds 5 --hitcount 2 -j DROP
iptables -A INPUT -p tcp --tcp-flags RST RST -j LOG --log-prefix "RST passed: "

echo 1 > /proc/sys/net/ipv4/ip_forward

