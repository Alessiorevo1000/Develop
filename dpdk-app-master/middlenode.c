#include <arpa/inet.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "crypto_dpdk.h"

#include <getopt.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf_dyn.h>
#include <stdalign.h>
#include <stdlib.h>
#define RX_RING_SIZE 2048
#define TX_RING_SIZE 2048
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 256
#define CUSTOM_HEADER_TYPE 0x0833

static int operation_bypass_bit = 0;

struct ipv6_srh {
  uint8_t next_header;  // Next header type
  uint8_t hdr_ext_len;  // Length of SRH in 8-byte units
  uint8_t routing_type; // Routing type (4 for SRv6)
  uint8_t segments_left;
  uint8_t last_entry;
  uint8_t flags;               // Segments yet to be visited
  uint8_t reserved[2];         // Reserved for future use
  struct in6_addr segments[2]; // Array of IPv6 segments max 10 nodes
};
struct hmac_tlv {
  uint8_t type;           // 1 byte for TLV type
  uint8_t length;         // 1 byte for TLV length
  uint16_t d_flag : 1;    // 1-bit D flag
  uint16_t reserved : 15; // Remaining 15 bits for reserved
  uint32_t hmac_key_id;   // 4 bytes for the HMAC Key ID
  uint8_t hmac_value[32]; // 8 Octets HMAC value must be multiples of 8 octetx
                          // and ma is 32 octets
};
struct pot_tlv {
  uint8_t type;               // Type field (1 byte)
  uint8_t length;             // Length field (1 byte)
  uint8_t reserved;           // Reserved field (1 byte)
  uint8_t nonce_length;       // Nonce Length field (1 byte)
  uint32_t key_set_id;        // Key Set ID (4 bytes)
  uint8_t nonce[16];          // Nonce (variable length)
  uint8_t encrypted_hmac[32]; // Encrypted HMAC (variable length)
};

/////////////////////////////////////////////////////////////
// Functions for packet timestamping
static int hwts_dynfield_offset = -1;

static inline rte_mbuf_timestamp_t *hwts_field(struct rte_mbuf *mbuf) {
  return RTE_MBUF_DYNFIELD(mbuf, hwts_dynfield_offset, rte_mbuf_timestamp_t *);
}

typedef uint64_t tsc_t;
static int tsc_dynfield_offset = -1;

static inline tsc_t *tsc_field(struct rte_mbuf *mbuf) {
  return RTE_MBUF_DYNFIELD(mbuf, tsc_dynfield_offset, tsc_t *);
}

static struct {
  uint64_t total_cycles;
  uint64_t total_queue_cycles;
  uint64_t total_pkts;
} latency_numbers;

static uint16_t add_timestamps(uint16_t port __rte_unused,
                               uint16_t qidx __rte_unused,
                               struct rte_mbuf **pkts, uint16_t nb_pkts,
                               uint16_t max_pkts __rte_unused,
                               void *_ __rte_unused) {
  unsigned i;
  uint64_t now = rte_rdtsc();

  for (i = 0; i < nb_pkts; i++)
    *tsc_field(pkts[i]) = now;
  return nb_pkts;
}

static uint16_t calc_latency(uint16_t port, uint16_t qidx __rte_unused,
                             struct rte_mbuf **pkts, uint16_t nb_pkts,
                             void *_ __rte_unused) {
  uint64_t cycles = 0;
  uint64_t queue_ticks = 0;
  uint64_t now = rte_rdtsc();
  uint64_t ticks;
  unsigned i;

  for (i = 0; i < nb_pkts; i++) {
    cycles += now - *tsc_field(pkts[i]);
  }

  latency_numbers.total_cycles += cycles;

  latency_numbers.total_pkts += nb_pkts;

  printf("Latency = %" PRIu64 " cycles\n",
         latency_numbers.total_cycles / latency_numbers.total_pkts);

  printf("number of packets: %" PRIu64 "\n", latency_numbers.total_pkts);

  double latency_us = (double)latency_numbers.total_cycles / rte_get_tsc_hz() *
                      1e6; // Convert to microseconds

  printf("Latency: %.3f µs\n", latency_us);

  latency_numbers.total_cycles = 0;
  latency_numbers.total_queue_cycles = 0;
  latency_numbers.total_pkts = 0;

  return nb_pkts;
}

//////////////////////////////////////////////////////////////

void display_mac_address(uint16_t port_id) {
  struct rte_ether_addr mac_addr;

  // Retrieve the MAC address of the specified port
  rte_eth_macaddr_get(port_id, &mac_addr);

  // Display the MAC address
  printf("MAC address of port %u: %02X:%02X:%02X:%02X:%02X:%02X\n", port_id,
         mac_addr.addr_bytes[0], mac_addr.addr_bytes[1], mac_addr.addr_bytes[2],
         mac_addr.addr_bytes[3], mac_addr.addr_bytes[4],
         mac_addr.addr_bytes[5]);
}

void print_ipv6_address(const struct in6_addr *ipv6_addr, const char *label) {
  char addr_str[INET6_ADDRSTRLEN]; // Buffer for human-readable address

  // Convert the IPv6 binary address to a string
  if (inet_ntop(AF_INET6, ipv6_addr, addr_str, sizeof(addr_str)) != NULL) {
    printf("%s: %s\n", label, addr_str);
  } else {
    perror("inet_ntop");
  }
}

void send_packet_to(struct rte_ether_addr mac_addr, struct rte_mbuf *mbuf,
                    uint16_t tx_port_id) {
  struct rte_ether_hdr *eth_hdr =
      rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

  // Compare the current destination MAC address to the broadcast address
  if (rte_is_broadcast_ether_addr(&eth_hdr->dst_addr) != 1) {
    // If it's not a broadcast address, update the destination MAC address
    rte_ether_addr_copy(&eth_hdr->dst_addr, &eth_hdr->src_addr);
    rte_ether_addr_copy(&mac_addr, &eth_hdr->dst_addr);
  }

  // Send the packets from the port no specified
  if (rte_eth_tx_burst(tx_port_id, 0, &mbuf, 1) == 0) {
    printf("Error sending packet\n");
    rte_pktmbuf_free(mbuf);
  } else {
    printf("IPV6 packet sent\n");
  }
  rte_pktmbuf_free(mbuf);
}
// Initialize a port
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	memset(&port_conf, 0, sizeof(struct rte_eth_conf));

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Starting Ethernet port. 8< */
	retval = rte_eth_dev_start(port);
	/* >8 End of starting of ethernet port. */
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port, RTE_ETHER_ADDR_BYTES(&addr));

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(port);
	/* End of setting RX port in promiscuous mode. */
	if (retval != 0)
		return retval;

	return 0;
}

// Decrypt function now uses DPDK Cryptodev for hardware acceleration
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext) {
  // Use DPDK cryptodev instead of OpenSSL
  return crypto_dpdk_decrypt(ciphertext, ciphertext_len, key, iv, plaintext);
}

int decrypt_pvf(uint8_t *k_pot_in, uint8_t *nonce, uint8_t pvf_out[32]) {
  uint8_t plaintext[128];
  int cipher_len = 32;
  printf("\n----------Decrypting with DPDK Cryptodev----------\n");
  
  // Use DPDK hardware-accelerated decryption
  int dec_len = crypto_dpdk_decrypt(pvf_out, cipher_len, k_pot_in, nonce, plaintext);
  
  if (dec_len < 0) {
    printf("ERROR: Hardware decryption failed\n");
    return -1;
  }
  
  printf("Decryption successful, length: %d bytes\n", dec_len);
  printf("Encrypted PVF: ");
  for (int j = 0; j < 32; j++) {
    printf("%02x", pvf_out[j]);
  }
  printf("\n");
  
  memcpy(pvf_out, plaintext, 32);
  
  printf("Decrypted PVF: ");
  for (int j = 0; j < 32; j++) {
    printf("%02x", plaintext[j]);
  }
  printf("\n");
  
  return 0;
}

void process_ip6_with_srh(struct rte_ether_hdr *eth_hdr, struct rte_mbuf *mbuf,
                          int i) {
  printf("\n###################################################################"
         "########\n");
  printf("\nip6 packet is encountered\n");
  struct ipv6_srh *srh;
  struct pot_tlv *pot;
  struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
  srh = (struct ipv6_srh *)(ipv6_hdr + 1); // SRH follows IPv6 header
  pot = (struct pot_tlv *)(srh + 1);

  printf("the proto nums are %d and %d\n", ipv6_hdr->proto, srh->next_header);
  if (srh->next_header == 61) {
    printf("segment routing detected\n");

    struct hmac_tlv *hmac;
    struct pot_tlv *pot;
    hmac = (struct hmac_tlv *)(srh + 1);
    pot = (struct pot_tlv *)(hmac + 1);
    // The key of this node (middle)
    uint8_t k_pot_in[32] = "eerreerreerreerreerreerreerreer";

    // FOR IPERF TESTING: IF THE DESTINATION MAC

    char target_ip[16];
    if (inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, target_ip, INET6_ADDRSTRLEN) ==
        NULL) {
      perror("inet_ntop failed");
      return;
    }
    printf("IPv6 address as string : %s\n", target_ip);

    // Display source and destination MAC addresses
    printf("Packet %d:\n", i + 1);
    printf("  Src MAC: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
           ":%02" PRIx8 ":%02" PRIx8 "\n",
           eth_hdr->src_addr.addr_bytes[0], eth_hdr->src_addr.addr_bytes[1],
           eth_hdr->src_addr.addr_bytes[2], eth_hdr->src_addr.addr_bytes[3],
           eth_hdr->src_addr.addr_bytes[4], eth_hdr->src_addr.addr_bytes[5]);
    printf("  Dst MAC: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
           ":%02" PRIx8 ":%02" PRIx8 "\n",
           eth_hdr->dst_addr.addr_bytes[0], eth_hdr->dst_addr.addr_bytes[1],
           eth_hdr->dst_addr.addr_bytes[2], eth_hdr->dst_addr.addr_bytes[3],
           eth_hdr->dst_addr.addr_bytes[4], eth_hdr->dst_addr.addr_bytes[5]);
    printf("  EtherType: 0x%04x\n", rte_be_to_cpu_16(eth_hdr->ether_type));

    print_ipv6_address((struct in6_addr *)&ipv6_hdr->src_addr, "source");
    print_ipv6_address((struct in6_addr *)&ipv6_hdr->dst_addr, "destination");

    // Get srh pointer after ipv6 header

    printf("The size of srh is %lu\n", sizeof(*srh));
    printf("The size of hmac is %lu\n", sizeof(*hmac));
    printf("The size of pot is %lu\n", sizeof(*pot));

    printf("HMAC type: %u\n", hmac->type);
    printf("HMAC length: %u\n", hmac->length);
    printf("HMAC key ID: %u\n", rte_be_to_cpu_32(hmac->hmac_key_id));
    printf("HMAC size: %ld\n", sizeof(hmac->hmac_value));

    // TODO burayı dinamik olarak bastır çünkü hmac 8 octet (8 byte 64 bit) veya
    // katı olabilir şimdilik i 1 den başıyor ve i-1 yazdırıyor
    printf("HMAC value: \n");
    for (int i = 0; i < 32; i++) {
      printf("%02x", hmac->hmac_value[i]);
    }
    printf("\nPVF value before decrypting: \n");
    for (int i = 0; i < 32; i++) {
      printf("%02x", pot->encrypted_hmac[i]);
    }
    // decrypyt one time with the key of node
    //  first declare the value to store decrypted pvf
    uint8_t pvf_out[32];
    memcpy(pvf_out, pot->encrypted_hmac, 32);
    decrypt_pvf(k_pot_in, pot->nonce, pvf_out);

    // update the pot header pvf field
    memcpy(pot->encrypted_hmac, pvf_out, 32);

    //fflush(stdout);
  }
}

void process_ip4(struct rte_mbuf *mbuf, uint16_t nb_rx,
                 struct rte_ether_hdr *eth_hdr, int i) {
  printf("number of the packets received is %d", nb_rx);

  struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);

  // Display source and destination MAC addresses
  printf("Packet %d:\n", i + 1);
  printf("  Src MAC: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
         ":%02" PRIx8 ":%02" PRIx8 "\n",
         eth_hdr->src_addr.addr_bytes[0], eth_hdr->src_addr.addr_bytes[1],
         eth_hdr->src_addr.addr_bytes[2], eth_hdr->src_addr.addr_bytes[3],
         eth_hdr->src_addr.addr_bytes[4], eth_hdr->src_addr.addr_bytes[5]);
  printf("  Dst MAC: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
         ":%02" PRIx8 ":%02" PRIx8 "\n",
         eth_hdr->dst_addr.addr_bytes[0], eth_hdr->dst_addr.addr_bytes[1],
         eth_hdr->dst_addr.addr_bytes[2], eth_hdr->dst_addr.addr_bytes[3],
         eth_hdr->dst_addr.addr_bytes[4], eth_hdr->dst_addr.addr_bytes[5]);
  printf("  EtherType: 0x%04x\n", rte_be_to_cpu_16(eth_hdr->ether_type));
  // If the packet is IPv4, display source and destination IP addresses

  printf("  Src IP: %d.%d.%d.%d\n", (ipv4_hdr->src_addr & 0xff),
         (ipv4_hdr->src_addr >> 8) & 0xff, (ipv4_hdr->src_addr >> 16) & 0xff,
         (ipv4_hdr->src_addr >> 24) & 0xff);
  printf("  Dst IP: %d.%d.%d.%d\n", (ipv4_hdr->dst_addr & 0xff),
         (ipv4_hdr->dst_addr >> 8) & 0xff, (ipv4_hdr->dst_addr >> 16) & 0xff,
         (ipv4_hdr->dst_addr >> 24) & 0xff);

  // Free the mbuf after processing
  rte_pktmbuf_free(mbuf);
}

void l_loop1(uint16_t rx_port_id, uint16_t tx_port_id) {
  printf("Capturing packets on port %d...\n", rx_port_id);
  struct rte_ether_addr egress_mac_addr = {
      {0x08, 0x00, 0x27, 0xF5, 0x60, 0xC2}};
  // Packet capture loop
  for (;;) {
    struct rte_mbuf *bufs[BURST_SIZE];
    uint16_t nb_rx = rte_eth_rx_burst(rx_port_id, 0, bufs, BURST_SIZE);

    if (unlikely(nb_rx == 0))
      continue;

    for (int i = 0; i < nb_rx; i++) {
      struct rte_mbuf *mbuf = bufs[i];
      struct rte_ether_hdr *eth_hdr =
          rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

      switch (rte_be_to_cpu_16(eth_hdr->ether_type)) {
      case RTE_ETHER_TYPE_IPV4:
        break;
      case RTE_ETHER_TYPE_IPV6:
        switch (operation_bypass_bit) {
        case 0:
          process_ip6_with_srh(eth_hdr, mbuf, i);
          send_packet_to(egress_mac_addr, mbuf, tx_port_id);
          printf("\n###########################################################"
                 "################\n");
          break;
        case 1:
          printf("All operations are bypassed. \n");
          send_packet_to(egress_mac_addr, mbuf, tx_port_id);
          break;
        }
      default:
        break;
      }
    }
  }
}

void l_loop2(uint16_t rx_port_id, uint16_t tx_port_id) {
  printf("Capturing packets on port %d...\n", rx_port_id);
  struct rte_ether_addr ingress_mac_addr = {
      {0x08, 0x00, 0x27, 0x91, 0x32, 0x3B}}; // rx port of middle node
  // Packet capture loop
  for (;;) {
    struct rte_mbuf *bufs[BURST_SIZE];
    uint16_t nb_rx = rte_eth_rx_burst(rx_port_id, 0, bufs, BURST_SIZE);

    if (unlikely(nb_rx == 0))
      continue;

    for (int i = 0; i < nb_rx; i++) {
      struct rte_mbuf *mbuf = bufs[i];
      struct rte_ether_hdr *eth_hdr =
          rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

      switch (rte_be_to_cpu_16(eth_hdr->ether_type)) {
      case RTE_ETHER_TYPE_IPV4:
        process_ip4(mbuf, nb_rx, eth_hdr, i);
        break;
      case RTE_ETHER_TYPE_IPV6:
        struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
        char target_ip[16];
        if (inet_ntop(AF_INET6, &ipv6_hdr->src_addr, target_ip,
                      INET6_ADDRSTRLEN) == NULL) {
          perror("inet_ntop failed");
          return;
        }

        printf("IPv6 Address (string format): %s\n", target_ip);

        const char *ip = "2001:db8:1::10";
        if (strncmp(target_ip, ip, INET6_ADDRSTRLEN) == 0) {
          printf("Packet is from iperf server \n");
          // edit the destination mac and source mac
          // tx port of ingress node packet goes C to B (A <--> B
          // <--> C <--> D)

          // send the packet to eggress node
          send_packet_to(ingress_mac_addr, mbuf, tx_port_id);
        }
        break;
      default:
        break;
      }
    }
  }
}

int lcore_main_forward(void *arg) {
  uint16_t *ports = (uint16_t *)arg;
  l_loop1(ports[0], ports[1]);
  return 0;
}

// for iperf returning packets
int lcore_main_forward2(void *arg) {
  uint16_t *ports = (uint16_t *)arg;
  l_loop2(ports[1], ports[0]);
  return 0;
}

int main(int argc, char *argv[]) {

  printf("Enter  (0-1): ");
  if (scanf("%u", &operation_bypass_bit) == 1) { // Read an unsigned integer
    if (operation_bypass_bit > 1 || operation_bypass_bit < 0) {
      printf("You entered: %u\n", operation_bypass_bit);
      rte_exit(EXIT_FAILURE, "Invalid argument\n");
    } else {
      printf("You entered: %u\n", operation_bypass_bit);
    }
  }

  struct rte_mempool *mbuf_pool;
  uint16_t port_id = 0;
  uint16_t tx_port_id = 1;

  static const struct rte_mbuf_dynfield tsc_dynfield_desc = {
      .name = "example_bbdev_dynfield_tsc",
      .size = sizeof(tsc_t),
      .align = alignof(tsc_t),
  };

  // Initialize the Environment Abstraction Layer (EAL)
  int ret = rte_eal_init(argc, argv);
  if (ret < 0)
    rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

  // Check that there is at least one port available
  if (rte_eth_dev_count_avail() == 0) {
    rte_exit(EXIT_FAILURE, "No Ethernet ports available\n");
  }

  // Create a memory pool to hold the mbufs
  mbuf_pool = rte_pktmbuf_pool_create(
      "MBUF_POOL", NUM_MBUFS * rte_eth_dev_count_avail(), MBUF_CACHE_SIZE, 0,
      RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
  if (mbuf_pool == NULL)
    rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

  // Initialize DPDK Cryptodev for hardware-accelerated crypto
  printf("\n=== Initializing DPDK Cryptodev ===\n");
  if (crypto_dpdk_init() < 0) {
    printf("WARNING: Failed to initialize crypto device\n");
    printf("Falling back to software crypto (if available)\n");
    // Don't exit - some systems may not have crypto devices
  }
  
  // Set mbuf pool for crypto operations
  crypto_dpdk_set_mbuf_pool(mbuf_pool);
  printf("=== Cryptodev initialization complete ===\n\n");

  tsc_dynfield_offset = rte_mbuf_dynfield_register(&tsc_dynfield_desc);
  if (tsc_dynfield_offset < 0)
    rte_exit(EXIT_FAILURE, "Cannot register mbuf field\n");

  // Initialize the port
  if (port_init(port_id, mbuf_pool) != 0) {
    rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", port_id);
  } else {
    rte_eth_add_rx_callback(port_id, 0, add_timestamps, NULL);
    display_mac_address(port_id);
  }

  if (port_init(tx_port_id, mbuf_pool) != 0) {
    rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", tx_port_id);
  } else {
    rte_eth_add_tx_callback(tx_port_id, 0, calc_latency, NULL);
    display_mac_address(tx_port_id);
  }

  // MAKE ALL INITIAL PRINTS HERE
  printf("TSC frequency: %" PRIu64 " Hz\n", rte_get_tsc_hz());
  unsigned lcore_id;
  uint16_t ports[2] = {port_id, tx_port_id};
  // lcore_id = rte_get_next_lcore(-1, 1, 0);
  // rte_eal_remote_launch(lcore_main_forward, (void *)ports, lcore_id);
  //lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
  //rte_eal_remote_launch(lcore_main_forward2, (void *)ports, lcore_id);
  lcore_main_forward((void *)ports);
  //rte_eal_mp_wait_lcore();

  // Cleanup crypto resources
  crypto_dpdk_cleanup();

  return 0;
}
