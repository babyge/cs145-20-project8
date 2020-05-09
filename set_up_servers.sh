#! /bin/bash
echo "Enter the Virtual IP"
read VIP
read -a list -p "Please give the hosts to set up into servers: "

for name in "${list[@]}"; do
	~/mininet/util/m $name ip addr add $VIP dev ${name}-eth0
done
