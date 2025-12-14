#!/bin/bash

# Crea bridge virbr1
if ! virsh net-info virbr1 &>/dev/null; then
  echo "Creo bridge virbr1..."
  cat > /tmp/virbr1.xml <<EOF
<network>
  <name>virbr1</name>
  <bridge name='virbr1' stp='on' delay='0'/>
  <ip address='192.168.101.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.101.2' end='192.168.101.254'/>
    </dhcp>
  </ip>
</network>
EOF
  sudo virsh net-define /tmp/virbr1.xml
  sudo virsh net-autostart virbr1
  sudo virsh net-start virbr1
  rm /tmp/virbr1.xml
else
  echo "virbr1 già esistente."
fi

# Crea bridge virbr2
if ! virsh net-info virbr2 &>/dev/null; then
  echo "Creo bridge virbr2..."
  cat > /tmp/virbr2.xml <<EOF
<network>
  <name>virbr2</name>
  <bridge name='virbr2' stp='on' delay='0'/>
  <ip address='192.168.102.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.102.2' end='192.168.102.254'/>
    </dhcp>
  </ip>
</network>
EOF
  sudo virsh net-define /tmp/virbr2.xml
  sudo virsh net-autostart virbr2
  sudo virsh net-start virbr2
  rm /tmp/virbr2.xml
else
  echo "virbr2 già esistente."
fi

echo "Bridge virbr1 e virbr2 pronti."
