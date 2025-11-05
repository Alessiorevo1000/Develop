#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <stdio.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_icmp.h>
#include <netinet/ip_icmp.h>


#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define PACKET_LEN 64
#define DEST_IP_ADDR  RTE_IPV4(10, 0, 2, 8)
#define SEND_INTERVAL 10000000 // Sending interval in microseconds


// Destination and source MAC addresses
static const struct rte_ether_addr dst_mac = { .addr_bytes = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff} };

static void print_port_stats(uint16_t port_id) {
    struct rte_eth_stats stats;
    rte_eth_stats_get(port_id, &stats);

    printf("Port %u stats:\n", port_id);
    printf("  RX packets: %lu\n", stats.ipackets);
    printf("  TX packets: %lu\n", stats.opackets);
    printf("  RX errors:  %lu\n", stats.ierrors);
    printf("  TX errors:  %lu\n", stats.oerrors);
    printf("  RX dropped: %lu\n", stats.imissed);
    printf("  RX no mbuf: %lu\n", stats.rx_nombuf);
}

static void send_ip_packet(struct rte_mempool *mbuf_pool, uint16_t port) {
    struct rte_mbuf *mbufs[BURST_SIZE];
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ip_hdr;
    struct rte_icmp_hdr *icmp_hdr;
    uint16_t pkt_len;
    char *data;
    const uint16_t payload_size = 14;

    for (int i = 0; i < BURST_SIZE; i++) {
        mbufs[i] = rte_pktmbuf_alloc(mbuf_pool);
        if (mbufs[i] == NULL) {
            printf("Error allocating mbuf\n");
            // Clean up any previously allocated mbufs
            for (int j = 0; j < i; j++) {
                rte_pktmbuf_free(mbufs[j]);
            }
            return;
        }

        pkt_len = sizeof(struct rte_ether_hdr) +
                  sizeof(struct rte_ipv4_hdr) +
                  sizeof(struct rte_icmp_hdr) +
                  payload_size;

        mbufs[i]->data_len = pkt_len;

        eth_hdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr *);

        /* Set Ethernet header. */
        rte_eth_macaddr_get(port, &eth_hdr->src_addr);  // Get source MAC address
        rte_ether_addr_copy(&dst_mac, &eth_hdr->dst_addr);
        eth_hdr->ether_type = htons(RTE_ETHER_TYPE_IPV4);

        /* Print MAC address */
        printf("Source MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
               eth_hdr->src_addr.addr_bytes[0], eth_hdr->src_addr.addr_bytes[1],
               eth_hdr->src_addr.addr_bytes[2], eth_hdr->src_addr.addr_bytes[3],
               eth_hdr->src_addr.addr_bytes[4], eth_hdr->src_addr.addr_bytes[5]);

        /* Set IP header. */
        ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
        ip_hdr->version_ihl = RTE_IPV4_VHL_DEF;
        ip_hdr->type_of_service = 0;
        ip_hdr->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr) + payload_size);
        ip_hdr->packet_id = rte_cpu_to_be_16(i + 1);  // Vary the packet ID
        ip_hdr->fragment_offset = 0;
        ip_hdr->time_to_live = 64;
        ip_hdr->next_proto_id = IPPROTO_ICMP;
        ip_hdr->src_addr = rte_cpu_to_be_32(RTE_IPV4(10, 0, 2, 44)); // Source IP
        ip_hdr->dst_addr = rte_cpu_to_be_32(DEST_IP_ADDR);              // Destination IP
        ip_hdr->hdr_checksum = 0;

        /* Initialize ICMP Header */
        icmp_hdr = (struct rte_icmp_hdr *)(ip_hdr + 1);
        icmp_hdr->icmp_type = RTE_IP_ICMP_ECHO_REQUEST;
        icmp_hdr->icmp_code = 0;
        icmp_hdr->icmp_ident = rte_cpu_to_be_16(1);
        icmp_hdr->icmp_seq_nb = rte_cpu_to_be_16(i + 1);  // Vary the sequence number
        icmp_hdr->icmp_cksum = 0;  // Reset checksum field to 0 before calculation


        /* Add payload. */
        /* Calculate ICMP checksum */
        icmp_hdr->icmp_cksum = rte_raw_cksum(icmp_hdr, sizeof(icmp_hdr));
        ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);

    }

    /* Send the packets. */
    for (int i = 0; i < BURST_SIZE; i++) {
        if (rte_eth_tx_burst(port, 0, &mbufs[i], 1) == 0) {
            printf("Error sending packet\n");
            rte_pktmbuf_free(mbufs[i]);
        } else {
            printf("Packet sent\n");
        }
    }
}

void continuous_send_receive_loop(struct rte_mempool *mbuf_pool, uint16_t port) {
    struct rte_mbuf *mbufs[BURST_SIZE];

    while (1) {
        // Send packets
        // Prepare the packet here (reuse your `send_ip_packet` logic)
            send_ip_packet(mbuf_pool, port);
        

        // Receive packets to keep the interface active
        uint16_t nb_rx = rte_eth_rx_burst(port, 0, mbufs, BURST_SIZE);
        if (nb_rx > 0) {
            for (int j = 0; j < nb_rx; j++) {
                rte_pktmbuf_free(mbufs[j]);  // Free received packets
            }
            printf("Received %d packets\n", nb_rx);
        }

        // Delay to control sending rate and prevent CPU overuse
        usleep(SEND_INTERVAL); // Control the polling interval
    }
}



int main(int argc, char *argv[]) {
    printf("I am working");
    struct rte_mempool *mbuf_pool;
    uint16_t portid;
    uint16_t nb_ports;
/*
    // Get the number of available ports
    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0)
    rte_exit(EXIT_FAILURE, "No available ports\n");
*/
    // Initialize DPDK EAL
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_panic("Cannot init EAL\n");
    argc -= ret;
    argv += ret;

    // Create a memory pool for storing packet buffers
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL) rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    // Initialize the port (e.g., port 0)
    portid = 0;
    if (!rte_eth_dev_is_valid_port(portid)) {
        rte_exit(EXIT_FAILURE, "Invalid port\n");
    }

    struct rte_eth_conf port_conf = {0};   
    if (rte_eth_dev_configure(portid, 1, 1, &port_conf) != 0) {
        rte_exit(EXIT_FAILURE, "Cannot configure device\n");
    }

    // Allocate and set up RX and TX queues
    if (rte_eth_rx_queue_setup(portid, 0, 128, rte_eth_dev_socket_id(portid), NULL, mbuf_pool) != 0) {
        rte_exit(EXIT_FAILURE, "RX queue setup failed\n");
    }
    if (rte_eth_tx_queue_setup(portid, 0, 128, rte_eth_dev_socket_id(portid), NULL) != 0) {
        rte_exit(EXIT_FAILURE, "TX queue setup failed\n");
    }

    // Start the Ethernet port
    if (rte_eth_dev_start(portid) != 0) {
        rte_exit(EXIT_FAILURE, "Device start failed\n");
    }

    // Generate and send packets
    //send_packets(mbuf_pool, portid);
    send_ip_packet(mbuf_pool,portid);

    //port stats
    print_port_stats(portid);

    continuous_send_receive_loop(mbuf_pool,portid);

    // Stop and close the port
    rte_eth_dev_stop(portid);
    rte_eth_dev_close(portid);

    return 0;
}


