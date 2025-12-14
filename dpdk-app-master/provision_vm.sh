#!/bin/bash
# Script di provisioning per VM Ubuntu
# Configura 3 interfacce di rete e installa pacchetti base

set -e

# Configurazione IP statici (modifica secondo necessità)
cat <<EOF | sudo tee /etc/netplan/01-netcfg.yaml
network:
  version: 2
  ethernets:
    ens3:
      dhcp4: no
      addresses: [192.168.100.10/24]
      gateway4: 192.168.100.1
      nameservers:
        addresses: [8.8.8.8,8.8.4.4]
    ens4:
      dhcp4: no
      addresses: [192.168.101.10/24]
    ens5:
      dhcp4: no
      addresses: [192.168.102.10/24]
EOF

sudo netplan apply

# Aggiorna pacchetti e installa tool base
sudo apt update
sudo apt install -y build-essential python3 python3-pip git

# Installa DPDK
sudo apt install -y dpdk dpdk-dev

# (Opzionale) Clona il tuo progetto se necessario
# git clone <repo-url>

# Messaggio finale
IP configurati e pacchetti installati. Personalizza gli indirizzi IP per ogni VM!
