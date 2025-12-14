#!/bin/bash
set -e

### PARAMETRI TRAFFIC ###########################################################

BR=pot-br

NS_TRAFFIC=ns_traffic
NS_CREATOR=ns_creator

# veth lato root (collegate a OVS)
VETHT_BR=veth_traffic-br
VETHC_BR=veth_creator-br

# veth lato namespace
VETHT=veth_traffic
VETHC=veth_creator

# MAC fittizi usati dai namespace per raggiungere i gateway IPv6
GW_TRAFFIC_MAC=00:00:cc:cc:cc:05
GW_CREATOR_MAC=00:00:aa:aa:aa:04

# Gateway IPv6 fittizi (NON locali, subnet diverse)
GW_TRAFFIC_IP=fd00:99::1
GW_CREATOR_IP=fd00:98::1

# IP reali inside the namespaces
TRAFFIC_IP=fd00:2::5/64
CREATOR_IP=fd00:2::4/64

# Reti remote per le route dummy (subnet diverse)
CREATOR_NET=fd00:3::/64
TRAFFIC_NET=fd00:4::/64

# NIC VirtualBox nel root namespace (parte del ring)
IF_RING_IN=enp1s0     # verso Creator
IF_RING_OUT=enp7s0    # verso Middle/Controller

#######################################################################

echo
 echo "[*] Pulizia configurazione precedente"
ip netns del "$NS_TRAFFIC" 2>/dev/null || true
ip netns del "$NS_CREATOR" 2>/dev/null || true
ovs-vsctl del-br "$BR" 2>/dev/null || true
ip link del "$VETHT_BR" 2>/dev/null || true
ip link del "$VETHC_BR" 2>/dev/null || true

echo
 echo "[*] Creazione bridge OVS e connessione NIC VirtualBox"

ovs-vsctl add-br "$BR"

ip addr flush dev "$IF_RING_IN"  || true
ip addr flush dev "$IF_RING_OUT" || true

ip link set "$IF_RING_IN" up
ip link set "$IF_RING_OUT" up

ovs-vsctl add-port "$BR" "$IF_RING_IN"
ovs-vsctl add-port "$BR" "$IF_RING_OUT"

echo
 echo "[*] Creazione namespaces"
ip netns add "$NS_TRAFFIC"
ip netns add "$NS_CREATOR"

echo
 echo "[*] Creazione veth e collegamento a namespaces + OVS"

# veth traffic
ip link add "$VETHT" type veth peer name "$VETHT_BR"
ip link set "$VETHT" netns "$NS_TRAFFIC"
ip link set "$VETHT_BR" up
ovs-vsctl add-port "$BR" "$VETHT_BR"

# veth creator
ip link add "$VETHC" type veth peer name "$VETHC_BR"
ip link set "$VETHC" netns "$NS_CREATOR"
ip link set "$VETHC_BR" up
ovs-vsctl add-port "$BR" "$VETHC_BR"

echo
 echo "[*] Configurazione IPv6 nei namespaces"

# TRAFFIC
ip netns exec "$NS_TRAFFIC" ip link set lo up
ip netns exec "$NS_TRAFFIC" ip link set "$VETHT" up
ip netns exec "$NS_TRAFFIC" ip -6 addr add "$TRAFFIC_IP" dev "$VETHT"
ip netns exec "$NS_TRAFFIC" ip -6 addr add "$GW_TRAFFIC_IP/64" dev "$VETHT"

# CREATOR
ip netns exec "$NS_CREATOR" ip link set lo up
ip netns exec "$NS_CREATOR" ip link set "$VETHC" up
ip netns exec "$NS_CREATOR" ip -6 addr add "$CREATOR_IP" dev "$VETHC"
ip netns exec "$NS_CREATOR" ip -6 addr add "$GW_CREATOR_IP/64" dev "$VETHC"

echo
 echo "[*] Rotte IPv6 dummy via gateway fittizi"

ip netns exec "$NS_TRAFFIC" ip -6 route add "$CREATOR_NET" via "$GW_TRAFFIC_IP"
ip netns exec "$NS_CREATOR" ip -6 route add "$TRAFFIC_NET" via "$GW_CREATOR_IP"

echo
 echo "[*] Neighbor statici (gateway → MAC fittizio)"

ip netns exec "$NS_TRAFFIC" ip -6 neigh add "$GW_TRAFFIC_IP" lladdr "$GW_TRAFFIC_MAC" dev "$VETHT" nud permanent
ip netns exec "$NS_CREATOR" ip -6 neigh add "$GW_CREATOR_IP" lladdr "$GW_CREATOR_MAC" dev "$VETHC" nud permanent

echo
 echo "[*] Abilitazione IPv6 forwarding"

sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
ip netns exec "$NS_TRAFFIC" sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
ip netns exec "$NS_CREATOR" sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null

echo
 echo "[*] Pulizia flow esistenti"
ovs-ofctl del-flows "$BR"

echo
 echo "[*] Calcolo MAC reali delle interfacce nei namespaces"

TRAFFIC_REAL_MAC=$(ip netns exec "$NS_TRAFFIC" ip link show "$VETHT" \
    | awk '/link\/ether/ {print $2}')
CREATOR_REAL_MAC=$(ip netns exec "$NS_CREATOR" ip link show "$VETHC" \
    | awk '/link\/ether/ {print $2}')

echo "  - MAC traffic ns: $TRAFFIC_REAL_MAC"
echo "  - MAC creator ns: $CREATOR_REAL_MAC"

# porte OpenFlow
PORT_VETHT_BR=$(ovs-vsctl get Interface "$VETHT_BR" ofport)
PORT_VETHC_BR=$(ovs-vsctl get Interface "$VETHC_BR" ofport)
PORT_RING_IN=$(ovs-vsctl get Interface "$IF_RING_IN" ofport)
PORT_RING_OUT=$(ovs-vsctl get Interface "$IF_RING_OUT" ofport)

echo
 echo "[*] Installazione flow OVS (NESSUNA REGOLA 4)"

##########################
# 1) TRAFFIC -> ANELLO
##########################
ovs-ofctl add-flow "$BR" \
"priority=100,in_port=$PORT_VETHT_BR,dl_dst=$GW_TRAFFIC_MAC,actions=mod_dl_dst:ff:ff:ff:ff:ff:ff,output:$PORT_RING_IN"

##########################
# 2) ANELLO -> CREATOR
##########################
ovs-ofctl add-flow "$BR" \
"priority=100,in_port=$PORT_RING_OUT,dl_dst=ff:ff:ff:ff:ff:ff,actions=mod_dl_dst:$CREATOR_REAL_MAC,output:$PORT_VETHC_BR"

##########################
# 3) CREATOR -> TRAFFIC (DIRECT, SENZA PASSARE DALL'ANELLO)
##########################
ovs-ofctl add-flow "$BR" \
"priority=100,in_port=$PORT_VETHC_BR,dl_dst=$GW_CREATOR_MAC,actions=mod_dl_dst:$TRAFFIC_REAL_MAC,output:$PORT_VETHT_BR"

echo
 echo "[*] Configurazione completata!"
echo
 echo "Test rapidi:"
echo "  - ping6 dal traffic al creator: ip netns exec $NS_TRAFFIC ping -6 $CREATOR_IP"
echo "  - ping6 dal creator al traffic: ip netns exec $NS_CREATOR ping -6 $TRAFFIC_IP"
echo "  - dump flussi:                ovs-ofctl dump-flows $BR"
echo
