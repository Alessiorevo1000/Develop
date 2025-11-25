// Melih
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

#include <getopt.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf_dyn.h>
#include <stdalign.h>
#include <stdlib.h>

// DPDK Cryptodev includes
#include <rte_crypto.h>
#include <rte_cryptodev.h>
#include <rte_mempool.h>

#define RX_RING_SIZE 2048
#define TX_RING_SIZE 2048
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define POOL_CACHE_SIZE 128
#define BURST_SIZE 256
#define CUSTOM_HEADER_TYPE 0x0833
#define SID_NO                                                                 \
  10 // Total 3 dpdk runnning nodes. 2 of them are sid1 and sid0(egress)
#define NONCE_LENGTH 16 // AES uses 16 bytes of iv
#define EXTRA_SPACE 128

#define HMAC_MAX_LENGTH 32 // Truncate HMAC to 32 bytes if needed
#define MAX_CRYPTO_SESSIONS 16
#define CRYPTO_OP_POOL_SIZE 1024
#define AES_KEY_LENGTH 32 // AES-256

static int operation_bypass_bit = 0;

// Global cryptodev variables
static uint8_t cdev_id = 0;
static struct rte_mempool *crypto_op_pool = NULL;
static struct rte_mempool *session_pool = NULL;
static struct rte_mempool *crypto_mbuf_pool = NULL;
static void *hmac_session = NULL;
static void *cipher_session = NULL;

// Function to initialize cryptodev
static int init_cryptodev(uint8_t socket_id) {
  struct rte_cryptodev_info dev_info;
  unsigned int session_size;

  // Check for available crypto devices
  uint8_t cdev_count = rte_cryptodev_count();
  printf("Found %d crypto device(s)\n", cdev_count);

  if (cdev_count == 0) {
    printf("ERROR: No crypto devices available!\n");
    printf("Run with: --vdev=crypto_aesni_mb\n");
    return -1;
  }

  // Get device info
  rte_cryptodev_info_get(cdev_id, &dev_info);
  printf("Using crypto device: %s\n", dev_info.driver_name);

  // Get session size - needed for session pool creation
  session_size = rte_cryptodev_sym_get_private_session_size(cdev_id);
  printf("Session private data size: %u bytes\n", session_size);

  // Create crypto mbuf pool
  crypto_mbuf_pool = rte_pktmbuf_pool_create(
      "crypto_mbuf_pool", NUM_MBUFS, MBUF_CACHE_SIZE, 0,
      RTE_MBUF_DEFAULT_BUF_SIZE + EXTRA_SPACE, socket_id);
  if (crypto_mbuf_pool == NULL) {
    printf("Cannot create crypto mbuf pool\n");
    return -1;
  }

  // Create crypto operation pool
  crypto_op_pool = rte_crypto_op_pool_create(
      "crypto_op_pool", RTE_CRYPTO_OP_TYPE_SYMMETRIC, CRYPTO_OP_POOL_SIZE,
      POOL_CACHE_SIZE, HMAC_MAX_LENGTH, socket_id);
  if (crypto_op_pool == NULL) {
    printf("Cannot create crypto op pool\n");
    return -1;
  }

  // Create session pool using rte_cryptodev_sym_session_pool_create
  // In DPDK 23.11, we need to use the proper session pool creation with correct
  // size
  session_pool = rte_cryptodev_sym_session_pool_create(
      "session_pool", MAX_CRYPTO_SESSIONS, session_size, 0, 0, socket_id);
  if (session_pool == NULL) {
    printf("Cannot create session pool (errno=%d)\n", rte_errno);
    return -1;
  }
  printf("Created session pool successfully\n");

  // Configure cryptodev
  struct rte_cryptodev_config conf = {
      .nb_queue_pairs = 1,
      .socket_id = socket_id,
      .ff_disable = 0,
  };

  if (rte_cryptodev_configure(cdev_id, &conf) < 0) {
    printf("Failed to configure cryptodev\n");
    return -1;
  }

  // Setup queue pair - mp_session may not be needed for all drivers
  struct rte_cryptodev_qp_conf qp_conf = {
      .nb_descriptors = 2048,
      .mp_session = NULL, // Set to NULL - driver will manage sessions
  };

  if (rte_cryptodev_queue_pair_setup(cdev_id, 0, &qp_conf, socket_id) < 0) {
    printf("Failed to setup queue pair\n");
    return -1;
  }
  printf("Queue pair setup successfully\n");

  // Start cryptodev
  if (rte_cryptodev_start(cdev_id) < 0) {
    printf("Failed to start cryptodev\n");
    return -1;
  }
  printf("Cryptodev started successfully\n");

  // Create HMAC session
  uint8_t hmac_key[] = "my-hmac-key-for-pvf-calculation";
  struct rte_crypto_sym_xform auth_xform = {
      .next = NULL,
      .type = RTE_CRYPTO_SYM_XFORM_AUTH,
      .auth = {.op = RTE_CRYPTO_AUTH_OP_GENERATE,
               .algo = RTE_CRYPTO_AUTH_SHA256_HMAC,
               .key = {.data = hmac_key, .length = 32},
               .digest_length = HMAC_MAX_LENGTH}};

  hmac_session =
      rte_cryptodev_sym_session_create(cdev_id, &auth_xform, session_pool);
  if (hmac_session == NULL) {
    printf("Failed to create HMAC session (errno=%d)\n", rte_errno);
    return -1;
  }
  printf("HMAC session created successfully\n");

  // Create cipher session for AES-256-CTR
  uint8_t cipher_key[AES_KEY_LENGTH] =
      "qqwwqqwwqqwwqqwwqqwwqqwwqqwwqqw"; // Default key
  struct rte_crypto_sym_xform cipher_xform = {
      .next = NULL,
      .type = RTE_CRYPTO_SYM_XFORM_CIPHER,
      .cipher = {.op = RTE_CRYPTO_CIPHER_OP_ENCRYPT,
                 .algo = RTE_CRYPTO_CIPHER_AES_CTR,
                 .key = {.data = cipher_key, .length = AES_KEY_LENGTH},
                 .iv = {.offset = offsetof(struct rte_crypto_op, sym) +
                                  sizeof(struct rte_crypto_sym_op),
                        .length = NONCE_LENGTH}}};

  cipher_session =
      rte_cryptodev_sym_session_create(cdev_id, &cipher_xform, session_pool);
  if (cipher_session == NULL) {
    printf("Failed to create cipher session (errno=%d)\n", rte_errno);
    return -1;
  }
  printf("Cipher session created successfully\n");

  printf("Cryptodev initialized successfully\n");
  return 0;
}
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

  printf("Latency: %.3f Âµs\n", latency_us);

  latency_numbers.total_cycles = 0;
  latency_numbers.total_queue_cycles = 0;
  latency_numbers.total_pkts = 0;

  return nb_pkts;
}

//////////////////////////////////////////////////////////////

// Initialize a port
static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
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
    printf("Error during getting device (port %u) info: %s\n", port,
           strerror(-retval));
    return retval;
  }

  if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
    port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

  /* Configure the Ethernet device. */
  retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
  if (retval != 0)
    return retval;

  retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
  if (retval != 0)
    return retval;

  /* Allocate and set up 1 RX queue per Ethernet port. */
  for (q = 0; q < rx_rings; q++) {
    retval = rte_eth_rx_queue_setup(
        port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
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

  printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8
         " %02" PRIx8 " %02" PRIx8 "\n",
         port, RTE_ETHER_ADDR_BYTES(&addr));

  /* Enable RX in promiscuous mode for the Ethernet device. */
  retval = rte_eth_promiscuous_enable(port);
  /* End of setting RX port in promiscuous mode. */
  if (retval != 0)
    return retval;

  return 0;
}

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
  struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);

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
    char ipv6_dst_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, ipv6_dst_str, INET6_ADDRSTRLEN);

    printf("IPV6 packet sent to MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth_hdr->dst_addr.addr_bytes[0], eth_hdr->dst_addr.addr_bytes[1],
           eth_hdr->dst_addr.addr_bytes[2], eth_hdr->dst_addr.addr_bytes[3],
           eth_hdr->dst_addr.addr_bytes[4], eth_hdr->dst_addr.addr_bytes[5]);
    printf("IPv6 Destination: %s\n", ipv6_dst_str);
  }
  rte_pktmbuf_free(mbuf);
}

void add_custom_header6(struct rte_mbuf *pkt) {

  struct ipv6_srh *srh_hdr;
  struct hmac_tlv *hmac_hdr;
  struct pot_tlv *pot_hdr;
  struct rte_ether_hdr *eth_hdr_6 =
      rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
  struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr_6 + 1);
  uint8_t *payload = (uint8_t *)(ipv6_hdr + 1);

  // --- FIX 1: Salva il protocollo originale (es. 58 per ICMPv6, 6 per TCP) ---
  uint8_t original_proto = ipv6_hdr->proto;

  // Assuming ip6 packets the size of ethernet header + ip6 header is 54 bytes
  size_t payload_size = rte_pktmbuf_pkt_len(pkt) - 54;

  uint8_t *tmp_payload = (uint8_t *)malloc(payload_size);
  if (tmp_payload == NULL) {
    printf("malloc failed\n");
    return;
  }
  // save the payload which will be deleted and added later
  memcpy(tmp_payload, payload, payload_size);

  // Remove the payload
  rte_pktmbuf_trim(pkt, payload_size);

  // Add the custom headers in order and finally add the payload
  srh_hdr = (struct ipv6_srh *)rte_pktmbuf_append(pkt, sizeof(struct ipv6_srh));
  hmac_hdr =
      (struct hmac_tlv *)rte_pktmbuf_append(pkt, sizeof(struct hmac_tlv));
  pot_hdr = (struct pot_tlv *)rte_pktmbuf_append(pkt, sizeof(struct pot_tlv));
  payload = (uint8_t *)rte_pktmbuf_append(pkt, payload_size);

  // Reinsert the payload
  memcpy(payload, tmp_payload, payload_size);
  free(tmp_payload);

  // Populate POT
  pot_hdr->type = 1;
  pot_hdr->length = 48;
  pot_hdr->reserved = 0;
  pot_hdr->nonce_length = 16;
  pot_hdr->key_set_id = rte_cpu_to_be_32(1234);
  memset(pot_hdr->nonce, 0, sizeof(pot_hdr->nonce));
  memset(pot_hdr->encrypted_hmac, 0, sizeof(pot_hdr->encrypted_hmac));

  // Populate HMAC
  hmac_hdr->type = 5;
  hmac_hdr->length = 16;
  hmac_hdr->d_flag = 0;
  hmac_hdr->reserved = 0;
  hmac_hdr->hmac_key_id = rte_cpu_to_be_32(1234);
  memset(hmac_hdr->hmac_value, 0, sizeof(hmac_hdr->hmac_value));

  // --- FIX 2: Usa il protocollo originale invece di 61 ---
  // Così il Controller saprà che dopo aver tolto SRH c'è un ICMPv6 (58) o TCP
  // (6)
  srh_hdr->next_header = original_proto;

  srh_hdr->hdr_ext_len = 2;
  srh_hdr->routing_type = 4;
  srh_hdr->last_entry = 0;
  srh_hdr->flags = 0;
  srh_hdr->segments_left = 1;
  memset(srh_hdr->reserved, 0, 2);

  struct in6_addr segments[] = {
      {.s6_addr = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x01}},
      {.s6_addr = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x01}}};

  memcpy(srh_hdr->segments, segments, sizeof(segments));

  // --- FIX 3: Imposta il protocollo dell'header IPv6 a Routing (43) ---
  ipv6_hdr->proto = 43; // IPPROTO_ROUTING

  // --- FIX 4: Aggiorna la lunghezza del payload nell'header IPv6 ---
  // La lunghezza deve includere tutti gli header di estensione + payload
  ipv6_hdr->payload_len =
      rte_cpu_to_be_16(pkt->pkt_len - sizeof(struct rte_ether_hdr) -
                       sizeof(struct rte_ipv6_hdr));

  printf("Custom header added. Next Proto set to: %d, IPv6 Proto set to: 43\n",
         original_proto);
}

void add_custom_header6_only_srh(struct rte_mbuf *pkt) {
  struct ipv6_srh *srh_hdr;
  struct hmac_tlv *hmac_hdr;
  struct pot_tlv *pot_hdr;
  struct rte_ether_hdr *eth_hdr_6 =
      rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
  struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr_6 + 1);
  uint8_t *payload = (uint8_t *)(ipv6_hdr + 1);

  // printf("Initial packet length: %u\n", rte_pktmbuf_pkt_len(pkt));

  // Assuming ip6 packets the size of ethernet header + ip6 header is 54 bytes
  size_t payload_size = rte_pktmbuf_pkt_len(pkt) - 54;
  // printf("Payload size: %lu\n", payload_size);
  uint8_t *tmp_payload = (uint8_t *)malloc(payload_size);
  if (tmp_payload == NULL) {
    printf("malloc failed\n");
  }
  // save the payload which will be deleted and added later
  memcpy(tmp_payload, payload, payload_size);

  // Remove the payload
  rte_pktmbuf_trim(pkt, payload_size);

  srh_hdr = (struct ipv6_srh *)rte_pktmbuf_append(pkt, sizeof(struct ipv6_srh));
  payload = (uint8_t *)rte_pktmbuf_append(pkt, payload_size);

  memcpy(payload, tmp_payload, payload_size);
  free(tmp_payload);

  // 61 Any host internal protocol
  srh_hdr->next_header = 61; // No Next Header in this example
  srh_hdr->hdr_ext_len =
      2; // Length of SRH in 8-byte units, excluding the first 8 bytes
  srh_hdr->routing_type = 4; // Routing type for SRH
  srh_hdr->last_entry = 0;
  srh_hdr->flags = 0;
  srh_hdr->segments_left = 1;      // 1 segment left to visit (can be adjusted)
  memset(srh_hdr->reserved, 0, 2); // Set reserved bytes to zero

  struct in6_addr segments[] = {
      {.s6_addr = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x01}}, // Segment 1
      {.s6_addr = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x01}} // Segment 2
  };

  // Copy the segments to the SRH
  memcpy(srh_hdr->segments, segments, sizeof(segments));
}

int calculate_hmac(uint8_t *src_addr, // Source IPv6 address (16 bytes)
                   const struct ipv6_srh
                       *srh, // Pointer to the IPv6 Segment Routing Header (SRH)
                   const struct hmac_tlv *hmac_tlv, // Pointer to the HMAC TLV
                   uint8_t *key,                    // Pre-shared key
                   size_t key_len,    // Length of the pre-shared key
                   uint8_t *hmac_out) // Output buffer for the HMAC (32 bytes)
{
  // Input text buffer for HMAC computation
  size_t segment_list_len = sizeof(srh->segments);

  size_t input_len =
      16 + 1 + 1 + 2 + 4 + segment_list_len; // IPv6 Source + Last Entry + Flags
                                             // + Length + Key ID + Segment List

  uint8_t input[input_len];

  // Fill the input buffer
  size_t offset = 0;
  memcpy(input + offset, src_addr, 16); // IPv6 Source Address
  offset += 16;

  input[offset++] = srh->last_entry; // Last Entry
  input[offset++] = srh->flags;      // Flags (D-bit + Reserved)

  input[offset++] =
      0; // Placeholder for Length (2 bytes, can be zero for this step)
  input[offset++] = 0;

  memcpy(input + offset, &hmac_tlv->hmac_key_id,
         sizeof(hmac_tlv->hmac_key_id)); // HMAC Key ID
  offset += sizeof(hmac_tlv->hmac_key_id);

  memcpy(input + offset, srh->segments, segment_list_len); // Segment List
  offset += segment_list_len;

  // Perform HMAC computation using DPDK Cryptodev
  struct rte_crypto_op *op;
  struct rte_mbuf *m;

  // Allocate crypto operation
  if (rte_crypto_op_bulk_alloc(crypto_op_pool, RTE_CRYPTO_OP_TYPE_SYMMETRIC,
                               &op, 1) == 0) {
    rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1,
            "Not enough crypto operations available\n");
    return -1;
  }

  // Allocate mbuf for data
  m = rte_pktmbuf_alloc(crypto_mbuf_pool);
  if (m == NULL) {
    rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1, "Failed to allocate mbuf\n");
    rte_crypto_op_free(op);
    return -1;
  }

  // Copy input data to mbuf
  char *mbuf_data = rte_pktmbuf_append(m, input_len);
  if (mbuf_data == NULL) {
    rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1, "Failed to append data to mbuf\n");
    rte_pktmbuf_free(m);
    rte_crypto_op_free(op);
    return -1;
  }
  memcpy(mbuf_data, input, input_len);

  op->sym->m_src = m;
  op->sym->auth.data.offset = 0;
  op->sym->auth.data.length = input_len;

  // Set digest pointer
  op->sym->auth.digest.data = hmac_out;
  op->sym->auth.digest.phys_addr = rte_mem_virt2iova(hmac_out);

  // Attach session
  if (rte_crypto_op_attach_sym_session(op, hmac_session) < 0) {
    rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1, "Failed to attach session\n");
    rte_pktmbuf_free(m);
    rte_crypto_op_free(op);
    return -1;
  }

  // Enqueue and dequeue
  uint16_t num_enqueued = rte_cryptodev_enqueue_burst(cdev_id, 0, &op, 1);
  if (num_enqueued == 0) {
    rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1, "Failed to enqueue crypto op\n");
    rte_pktmbuf_free(m);
    rte_crypto_op_free(op);
    return -1;
  }

  struct rte_crypto_op *dequeued_op;
  uint16_t num_dequeued = 0;
  while (num_dequeued == 0) {
    num_dequeued = rte_cryptodev_dequeue_burst(cdev_id, 0, &dequeued_op, 1);
  }

  if (dequeued_op->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
    rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1, "Crypto operation failed\n");
    rte_pktmbuf_free(m);
    rte_crypto_op_free(dequeued_op);
    return -1;
  }

  // Cleanup
  rte_pktmbuf_free(m);
  rte_crypto_op_free(dequeued_op);

  return 0; // Success
}

// Calculates the PVF using the output of calulcate_hmac function with key
// k_hmac_ie

int generate_nonce(uint8_t nonce[NONCE_LENGTH]) {
  // Generate random nonce using rte_rand()
  for (int i = 0; i < NONCE_LENGTH; i++) {
    nonce[i] = (uint8_t)(rte_rand() & 0xFF);
  }
  // printf("Generated Nonce: ");
  for (int i = 0; i < NONCE_LENGTH; i++) {
    printf("%02x", nonce[i]);
  }
  // printf("\n");
  return 0;
}
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext) {
  struct rte_crypto_op *op;
  struct rte_mbuf *m;

  // Allocate crypto operation
  if (rte_crypto_op_bulk_alloc(crypto_op_pool, RTE_CRYPTO_OP_TYPE_SYMMETRIC,
                               &op, 1) == 0) {
    printf("Not enough crypto operations available\n");
    return -1;
  }

  // Allocate mbuf for data
  m = rte_pktmbuf_alloc(crypto_mbuf_pool);
  if (m == NULL) {
    printf("Failed to allocate mbuf\n");
    rte_crypto_op_free(op);
    return -1;
  }

  // Copy input data to mbuf
  char *mbuf_data = rte_pktmbuf_append(m, plaintext_len);
  if (mbuf_data == NULL) {
    printf("Failed to append data to mbuf\n");
    rte_pktmbuf_free(m);
    rte_crypto_op_free(op);
    return -1;
  }
  memcpy(mbuf_data, plaintext, plaintext_len);

  op->sym->m_src = m;
  op->sym->cipher.data.offset = 0;
  op->sym->cipher.data.length = plaintext_len;

  // Set IV - copy to the operation's private data area
  uint8_t *iv_ptr = rte_crypto_op_ctod_offset(
      op, uint8_t *,
      offsetof(struct rte_crypto_op, sym) + sizeof(struct rte_crypto_sym_op));
  memcpy(iv_ptr, iv, NONCE_LENGTH);

  // Attach session
  if (rte_crypto_op_attach_sym_session(op, cipher_session) < 0) {
    printf("Failed to attach cipher session\n");
    rte_pktmbuf_free(m);
    rte_crypto_op_free(op);
    return -1;
  }

  // Enqueue and dequeue
  uint16_t num_enqueued = rte_cryptodev_enqueue_burst(cdev_id, 0, &op, 1);
  if (num_enqueued == 0) {
    printf("Failed to enqueue crypto op\n");
    rte_pktmbuf_free(m);
    rte_crypto_op_free(op);
    return -1;
  }

  struct rte_crypto_op *dequeued_op;
  uint16_t num_dequeued = 0;
  while (num_dequeued == 0) {
    num_dequeued = rte_cryptodev_dequeue_burst(cdev_id, 0, &dequeued_op, 1);
  }

  if (dequeued_op->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
    printf("Crypto operation failed\n");
    rte_pktmbuf_free(m);
    rte_crypto_op_free(dequeued_op);
    return -1;
  }

  // Copy encrypted data back
  uint8_t *encrypted_data = rte_pktmbuf_mtod(m, uint8_t *);
  memcpy(ciphertext, encrypted_data, plaintext_len);

  // Cleanup
  rte_pktmbuf_free(m);
  rte_crypto_op_free(dequeued_op);

  return plaintext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext) {
  // Decryption using AES-CTR is identical to encryption due to its nature
  return encrypt(ciphertext, ciphertext_len, key, iv, plaintext);
}

void encrypt_pvf(uint8_t k_pot_in[SID_NO][HMAC_MAX_LENGTH], uint8_t *nonce,
                 uint8_t hmac_out[32]) {
  // k_pot_in is a 2d array of strings holding statically allocated keys for the
  // nodes. In this proof of concept there is only one middle node and an egress
  // node so the shape is [2][key-length]
  uint8_t ciphertext[128];
  uint8_t plaintext[128];
  printf("\n----------Encrypting----------\n");
  for (int i = 0; i < SID_NO; i++) {
    // printf("---Iteration: %d---\n", i);
    // printf("original text is:\n");
    for (int j = 0; j < HMAC_MAX_LENGTH; j++) {
      printf("%02x", hmac_out[j]);
    }
    // printf("\n");
    // printf("PVF size : %ld\n", strnlen(hmac_out, HMAC_MAX_LENGTH));
    int cipher_len =
        encrypt(hmac_out, HMAC_MAX_LENGTH, k_pot_in[i], nonce, ciphertext);
    // printf("The cipher length is : %d\n", cipher_len);

    // printf("Ciphertext is : \n");
    // BIO_dump_fp(stdout, (const char *)ciphertext, cipher_len);
    memcpy(hmac_out, ciphertext, 32);
    // printf("\n");
  }
}

int decrypt_pvf(uint8_t k_pot_in[SID_NO][HMAC_MAX_LENGTH], uint8_t *nonce,
                uint8_t pvf_out[32]) {
  // k_pot_in is a 2d array of strings holding statically allocated keys for the
  // nodes. In this proof of concept there is only one middle node and an egress
  // node so the shape is [2][key-length]
  uint8_t plaintext[128];
  int cipher_len = 32;
  printf("\n----------Decrypting----------\n");
  for (int i = SID_NO - 1; i >= 0; i--) {
    printf("---Iteration: %d---\n", i);
    int dec_len = decrypt(pvf_out, cipher_len, k_pot_in[i], nonce, plaintext);
    printf("Dec len %d\n", dec_len);
    printf("original text is:\n");
    for (int j = 0; j < HMAC_MAX_LENGTH; j++) {
      printf("%02x", pvf_out[j]);
    }
    printf("\n");
    memcpy(pvf_out, plaintext, 32);
    printf("Decrypted text is : \n");
    for (int j = 0; j < dec_len; j++) {
      printf("%02x ", pvf_out[j]);
      if ((j + 1) % 16 == 0)
        printf("\n");
    }
    printf("\n");
  }
  return 0;
}

int l_loop1(uint16_t rx_port_id, uint16_t tx_port_id) {
  printf("Capturing packets on port %d...\n", rx_port_id);
  struct rte_ether_addr middle_node_mac_addr = {
      {0x08, 0x00, 0x27, 0xC6, 0x79, 0x2A}}; // rx port of middle node

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
          printf("\n#######################################################\n");
          // 2 options here the packets already containing srh and the packets
          // does not contain
          // TODO CHECK Ä°P6 hdr if next_header field is 43 to determine if the
          // packet is srh
          add_custom_header6(mbuf);

          struct ipv6_srh *srh;
          struct hmac_tlv *hmac;
          struct pot_tlv *pot;
          // realigning the hmac header since we added new headers the address
          // is changed(bu alignment Ä± beÄŸenmiyorum deÄŸiÅŸtir)
          struct rte_ether_hdr *eth_hdr =
              rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
          struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
          srh = (struct ipv6_srh *)(ipv6_hdr + 1); // SRH follows IPv6 header
          hmac = (struct hmac_tlv *)(srh + 1);
          pot = (struct pot_tlv *)(hmac + 1);

          uint8_t hmac_out[HMAC_MAX_LENGTH];
          uint8_t k_hmac_ie[] = "my-hmac-key-for-pvf-calculation";
          uint8_t nonce[NONCE_LENGTH];
          size_t key_len = strlen((char *)k_hmac_ie);

          // FOR PROOF OF CONCEPT THIS IS NOT DYNAMIC
          // NORMALLY THÄ°S SHOULD BE DYNAMIC ACCORDING TO THE NODES IN THE
          // TOPOLOGY OR SPECIFIALLY ESPECTED PATH OF THE PACKET can use malloc
          // *
          char target_ip[16];
          inet_pton(AF_INET6, "2001:db8:1::1", target_ip);

          if (inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, target_ip,
                        INET6_ADDRSTRLEN) == NULL) {
            perror("inet_ntop failed");
            return 1;
          }

          // printf("IPv6 Address (string format): %s\n", target_ip);

          const char *ip1 = "2001:db8:1::6";
          const char *ip2 = "2001:db8:1::8";
          const char *ip3 = "2001:db8:1::10";
          uint8_t k_pot_in[SID_NO][HMAC_MAX_LENGTH];

          if (strncmp(target_ip, ip2, INET6_ADDRSTRLEN) == 0) {
            uint8_t temp[SID_NO][HMAC_MAX_LENGTH] = {
                "qqwwqqwwqqwwqqwwqqwwqqwwqqwwqqw",
                "eerreerreerreerreerreerreerreer",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
            memcpy(k_pot_in, temp, sizeof(temp));
          } else if (strncmp(target_ip, ip1, INET6_ADDRSTRLEN) == 0) {
            uint8_t temp[SID_NO][HMAC_MAX_LENGTH] = {
                "ttyyttyyttyyttyyttyyttyyttyytty",
                "eerreerreerreerreerreerreerreer"};
            memcpy(k_pot_in, temp, sizeof(temp));
          }
          // IPERF SETUP CODE FORWARD IT TO SERVER BY SWAPPING MAC ADDRESSES SO
          // THE VIRTUAL SWITCH CAN FORWARD IT TO NEXT MACHINE
          if (strncmp(target_ip, ip3, INET6_ADDRSTRLEN) == 0) {
            uint8_t temp[SID_NO][HMAC_MAX_LENGTH] = {
                "qqwwqqwwqqwwqqwwqqwwqqwwqqwwqqw",
                "eerreerreerreerreerreerreerreer"};
            memcpy(k_pot_in, temp, sizeof(temp));
          }

          // key of the last node is first

          // Compute HMAC
          if (calculate_hmac(ipv6_hdr->src_addr, srh, hmac, k_hmac_ie, key_len,
                             hmac_out) == 0) {
            printf("HMAC Computation Successful\n");
            printf("HMAC: ");
            for (int i = 0; i < HMAC_MAX_LENGTH; i++) {
              printf("%02x", hmac_out[i]);
            }
            // Write the hmac value in hmac header
            printf("\n");
            memcpy(hmac->hmac_value, hmac_out, 32);
            printf("HMAC value inserted to srh_hmac header\n");
          } else {
            printf("HMAC Computation Failed\n");
          }

          if (generate_nonce(nonce) != 0) {
            printf("Nonce generation failed retuning\n ");
            return 1;
          }
          encrypt_pvf(k_pot_in, nonce, hmac_out);

          printf("Ecrypted PVF before writing to the header: ");
          for (int i = 0; i < HMAC_MAX_LENGTH; i++) {
            printf("%02x", hmac_out[i]);
          }
          // Write the hmac value in hmac header
          printf("\n");
          memcpy(pot->encrypted_hmac, hmac_out, 32);
          memcpy(pot->nonce, nonce, 16);
          printf("Encrypted PVF and nonce values inserted to pot header\n");

          // Decrypt fpr testing purposes, this is the task for middle and
          // egress nodes decrypt_pvf(k_pot_in, nonce, hmac_out);

          // send the packets back with added custom header

          send_packet_to(middle_node_mac_addr, mbuf, tx_port_id);
          printf("\n#######################################################\n");
          break;
        case 1:
          printf("\n#######################################################\n");
          printf("All operations are bypassed. \n");
          send_packet_to(middle_node_mac_addr, mbuf, tx_port_id);
          printf("\n#######################################################\n");
          break;
        case 2:
          printf("\n#######################################################\n");
          add_custom_header6_only_srh(mbuf);
          // for iperf testing swap the mac address (normally the scapy
          // generated packets have broadcast dest mac)
          send_packet_to(middle_node_mac_addr, mbuf, tx_port_id);
          printf("\n#######################################################\n");
          break;

        default:
          // printf("\nonly ip4 or ip6 ethernet headers accepted\n");
          break;
        }
        // Free the mbuf after processing
        rte_pktmbuf_free(mbuf);
      }
    }
  }
}

void l_loop2(uint16_t rx_port_id, uint16_t tx_port_id) {
  printf("Capturing packets on port %d...\n", rx_port_id);
  struct rte_ether_addr traffic_mac_addr = {
      {0x08, 0x00, 0x27, 0x0F, 0xAC, 0x33}}; // rx port of middle node
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
      case RTE_ETHER_TYPE_IPV6: {
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
          // tx port of traffic generator node packet goes B to A
          // (A <--> B <--> C <--> D)
          send_packet_to(traffic_mac_addr, mbuf, tx_port_id);
        }
        break;
      }
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

  printf("Enter  (0-1-2): ");
  if (scanf("%u", &operation_bypass_bit) == 1) { // Read an unsigned integer
    if (operation_bypass_bit > 2 || operation_bypass_bit < 0) {
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

  printf("EAL initialization completed successfully\n");
  fflush(stdout);

  // Initialize cryptodev
  uint8_t socket_id = rte_socket_id();
  if (init_cryptodev(socket_id) < 0)
    rte_exit(EXIT_FAILURE, "Error with Cryptodev initialization\n");

  // Check that there is at least one port available
  uint16_t portcount = 0;
  if (rte_eth_dev_count_avail() == 0) {
    rte_exit(EXIT_FAILURE, "No Ethernet ports available\n");
  } else {
    portcount = rte_eth_dev_count_total();
    printf("number of ports: %d \n", (int)portcount);
  }

  // Create a memory pool to hold the mbufs
  mbuf_pool = rte_pktmbuf_pool_create(
      "MBUF_POOL", NUM_MBUFS * rte_eth_dev_count_avail(), MBUF_CACHE_SIZE, 0,
      RTE_MBUF_DEFAULT_BUF_SIZE + EXTRA_SPACE, rte_socket_id());
  if (mbuf_pool == NULL)
    rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

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
  lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
  // rte_eal_remote_launch(lcore_main_forward2, (void *)ports, lcore_id);
  lcore_main_forward((void *)ports);
  // rte_eal_mp_wait_lcore();

  return 0;
}