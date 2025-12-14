#!/bin/bash
# Provisioning per creator
set -e
cat <<EOF | sudo tee /etc/netplan/01-netcfg.yaml
network:
  version: 2
  ethernets:
    ens3:
      dhcp4: no
      addresses: [192.168.100.12/24]
      gateway4: 192.168.100.1
      nameservers:
        addresses: [8.8.8.8,8.8.4.4]
    ens4:
      dhcp4: no
      addresses: [192.168.101.12/24]
    ens5:
      dhcp4: no
      addresses: [192.168.102.12/24]
EOF
sudo netplan apply
sudo apt update
sudo apt install -y build-essential python3 python3-pip git dpdk dpdk-dev
