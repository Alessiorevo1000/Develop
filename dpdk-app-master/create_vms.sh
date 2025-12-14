#!/bin/bash

# Scarica la ISO di Ubuntu 22.04 se non presente
ISO_PATH="$PWD/ubuntu-22.04-live-server-amd64.iso"
if [ ! -f "$ISO_PATH" ]; then
  echo "Scarico Ubuntu 22.04 ISO..."
  wget -O "$ISO_PATH" https://releases.ubuntu.com/22.04/ubuntu-22.04.4-live-server-amd64.iso
fi

# Parametri comuni
RAM=2048
VCPUS=2
DISK_SIZE=20
OS_VARIANT=ubuntu22.04
BRIDGE1=virbr0
BRIDGE2=virbr1
BRIDGE3=virbr2

# Funzione per creare una VM
create_vm() {
  NAME=$1
  echo "Creo VM: $NAME"
  sudo virt-install \
    --name "$NAME" \
    --ram $RAM \
    --vcpus $VCPUS \
    --disk size=$DISK_SIZE \
    --os-type linux \
    --os-variant $OS_VARIANT \
    --network bridge=$BRIDGE1 \
    --network bridge=$BRIDGE2 \
    --network bridge=$BRIDGE3 \
    --graphics vnc \
    --cdrom "$ISO_PATH" \
    --noautoconsole
}

# Crea le 4 VM
create_vm traffic-server
create_vm creator
create_vm middle
create_vm controller

echo "Tutte le VM sono state create. Completa l'installazione tramite VNC o virt-manager."
