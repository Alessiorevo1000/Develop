#!/bin/bash
set -e

### PARAMETRI ###########################################################

BR=pot-br

NS_CLIENT=ns_client
NS_SERVER=ns_server

# veth lato root (collegate a OVS)
VETHC_BR=veth_client-br
VETHS_BR=veth_server-br

# veth lato namespace
VETHC=veth_client
VETHS=veth_server

# MAC fittizi usati dai namespace per raggiungere i gateway IPv6
GW_CLIENT_MAC=00:00:aa:aa:aa:01
GW_SERVER_MAC=00:00:bb:bb:bb:02

# Gateway IPv6 fittizi (non esistono fisicamente)
GW_CLIENT_IP=2001:db8:1::1
GW_SERVER_IP=2001:db8:2::1

# IP reali inside the namespaces
CLIENT_IP=2001:db8:1::2/64
SERVER_IP=2001:db8:2::2/64

# Reti remote per le route dummy
SERVER_NET=2001:db8:2::/64
CLIENT_NET=2001:db8:1::/64

# NIC VirtualBox nel root namespace (parte del ring)
IF_RING_IN=enp0s3     # verso ingress
IF_RING_OUT=enp0s8    # verso egress

#######################################################################

echo
echo "[*] Pulizia configurazione precedente"
ip netns del "$NS_CLIENT" 2>/dev/null || true
ip netns del "$NS_SERVER" 2>/dev/null || true
ovs-vsctl del-br "$BR" 2>/dev/null || true
ip link del "$VETHC_BR" 2>/dev/null || true
ip link del "$VETHS_BR" 2>/dev/null || true

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
ip netns add "$NS_CLIENT"
ip netns add "$NS_SERVER"

echo
echo "[*] Creazione veth e collegamento a namespaces + OVS"

# veth client
ip link add "$VETHC" type veth peer name "$VETHC_BR"
ip link set "$VETHC" netns "$NS_CLIENT"
ip link set "$VETHC_BR" up
ovs-vsctl add-port "$BR" "$VETHC_BR"

# veth server
ip link add "$VETHS" type veth peer name "$VETHS_BR"
ip link set "$VETHS" netns "$NS_SERVER"
ip link set "$VETHS_BR" up
ovs-vsctl add-port "$BR" "$VETHS_BR"

echo
echo "[*] Configurazione IPv6 nei namespaces"

# CLIENT
ip netns exec "$NS_CLIENT" ip link set lo up
ip netns exec "$NS_CLIENT" ip link set "$VETHC" up
ip netns exec "$NS_CLIENT" ip -6 addr add "$CLIENT_IP" dev "$VETHC"

# SERVER
ip netns exec "$NS_SERVER" ip link set lo up
ip netns exec "$NS_SERVER" ip link set "$VETHS" up
ip netns exec "$NS_SERVER" ip -6 addr add "$SERVER_IP" dev "$VETHS"

echo
echo "[*] Rotte IPv6 dummy via gateway fittizi"

ip netns exec "$NS_CLIENT" ip -6 route add "$SERVER_NET" via "$GW_CLIENT_IP"
ip netns exec "$NS_SERVER" ip -6 route add "$CLIENT_NET" via "$GW_SERVER_IP"

echo
echo "[*] Neighbor statici (gateway → MAC fittizio)"

ip netns exec "$NS_CLIENT" ip -6 neigh add "$GW_CLIENT_IP" lladdr "$GW_CLIENT_MAC" dev "$VETHC" nud permanent
ip netns exec "$NS_SERVER" ip -6 neigh add "$GW_SERVER_IP" lladdr "$GW_SERVER_MAC" dev "$VETHS" nud permanent

echo
echo "[*] Abilitazione IPv6 forwarding"

sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
ip netns exec "$NS_CLIENT" sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
ip netns exec "$NS_SERVER" sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null

echo
echo "[*] Pulizia flow esistenti"
ovs-ofctl del-flows "$BR"

echo
echo "[*] Calcolo MAC reali delle interfacce nei namespaces"

CLIENT_REAL_MAC=$(ip netns exec "$NS_CLIENT" ip link show "$VETHC" \
    | awk '/link\/ether/ {print $2}')
SERVER_REAL_MAC=$(ip netns exec "$NS_SERVER" ip link show "$VETHS" \
    | awk '/link\/ether/ {print $2}')

echo "  - MAC client ns: $CLIENT_REAL_MAC"
echo "  - MAC server ns: $SERVER_REAL_MAC"

# porte OpenFlow
PORT_VETHC_BR=$(ovs-vsctl get Interface "$VETHC_BR" ofport)
PORT_VETHS_BR=$(ovs-vsctl get Interface "$VETHS_BR" ofport)
PORT_RING_IN=$(ovs-vsctl get Interface "$IF_RING_IN" ofport)
PORT_RING_OUT=$(ovs-vsctl get Interface "$IF_RING_OUT" ofport)

echo
echo "[*] Installazione flow OVS (NESSUNA REGOLA 4)"

##########################
# 1) CLIENT -> ANELLO
##########################
ovs-ofctl add-flow "$BR" \
"priority=100,in_port=$PORT_VETHC_BR,dl_dst=$GW_CLIENT_MAC,actions=mod_dl_dst:ff:ff:ff:ff:ff:ff,output:$PORT_RING_IN"

##########################
# 2) ANELLO -> SERVER
##########################
ovs-ofctl add-flow "$BR" \
"priority=100,in_port=$PORT_RING_OUT,dl_dst=ff:ff:ff:ff:ff:ff,actions=mod_dl_dst:$SERVER_REAL_MAC,output:$PORT_VETHS_BR"

##########################
# 3) SERVER -> CLIENT (DIRECT, SENZA PASSARE DALL'ANELLO)
##########################
ovs-ofctl add-flow "$BR" \
"priority=100,in_port=$PORT_VETHS_BR,dl_dst=$GW_SERVER_MAC,actions=mod_dl_dst:$CLIENT_REAL_MAC,output:$PORT_VETHC_BR"

echo
echo "[*] Configurazione completata!"
echo
echo "Test rapidi:"
echo "  - ping6 dal client al server: ip netns exec $NS_CLIENT ping -6 $SERVER_IP"
echo "  - ping6 dal server al client: ip netns exec $NS_SERVER ping -6 $CLIENT_IP"
echo "  - dump flussi:                ovs-ofctl dump-flows $BR"
echo