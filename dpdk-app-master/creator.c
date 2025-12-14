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

#define RX_RING_SIZE 4096
#define TX_RING_SIZE 4096
#define NUM_MBUFS 16383
#define MBUF_CACHE_SIZE 512
#define POOL_CACHE_SIZE 256
#define BURST_SIZE 32
#define CUSTOM_HEADER_TYPE 0x0833
#define SID_NO                                                                 \
  10 // Total 3 dpdk runnning nodes. 2 of them are sid1 and sid0(egress)
#define NONCE_LENGTH 16 // AES uses 16 bytes of iv
#define EXTRA_SPACE 256

#define HMAC_MAX_LENGTH 32 // Truncate HMAC to 32 bytes if needed
#define MAX_CRYPTO_SESSIONS 16
#define CRYPTO_OP_POOL_SIZE 8192
#define AES_KEY_LENGTH 32 // AES-256
#define CRYPTO_BATCH_SIZE 32 // Process crypto ops in batches

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
      .nb_descriptors = 4096,
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

  // Sostituisci con:
  uint8_t cipher_key[AES_KEY_LENGTH] = "eerreerreerreerreerreerreerreer";
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

// Latency logging buffer to reduce I/O overhead
#define LATENCY_LOG_BUFFER_SIZE 1024
static struct {
  uint64_t pkt_num;
  double latency_us;
  uint16_t pkt_len;
} latency_log_buffer[LATENCY_LOG_BUFFER_SIZE];
static uint32_t latency_log_idx = 0;
static uint64_t latency_flush_threshold = 512; // Flush every N packets

static void flush_latency_log(void) {
  for (uint32_t i = 0; i < latency_log_idx; i++) {
    printf("[%6lu] %8.2f µs  %4u bytes\n",
           latency_log_buffer[i].pkt_num,
           latency_log_buffer[i].latency_us,
           latency_log_buffer[i].pkt_len);
  }
  latency_log_idx = 0;
}

static uint16_t calc_latency(uint16_t port __rte_unused, uint16_t qidx __rte_unused,
                             struct rte_mbuf **pkts, uint16_t nb_pkts,
                             void *_ __rte_unused) {
  static uint64_t tsc_hz = 0;
  static uint64_t pkt_counter = 0;
  uint64_t now = rte_rdtsc();
  
  // Cache TSC frequency once
  if (tsc_hz == 0) {
    tsc_hz = rte_get_tsc_hz();
  }

  for (unsigned i = 0; i < nb_pkts; i++) {
    uint64_t cycles = now - *tsc_field(pkts[i]);
    double latency_us = (double)cycles * 1e6 / tsc_hz;
    pkt_counter++;
    
    // Buffer the log entry instead of printing immediately
    if (latency_log_idx < LATENCY_LOG_BUFFER_SIZE) {
      latency_log_buffer[latency_log_idx].pkt_num = pkt_counter;
      latency_log_buffer[latency_log_idx].latency_us = latency_us;
      latency_log_buffer[latency_log_idx].pkt_len = pkts[i]->pkt_len;
      latency_log_idx++;
    }
  }
  
  // Flush buffer periodically to avoid memory buildup
  if (latency_log_idx >= latency_flush_threshold) {
    flush_latency_log();
  }

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

  /* Set MTU to 1700 to accommodate SRH/HMAC/POT headers (~136 bytes) */
  retval = rte_eth_dev_set_mtu(port, 1700);
  if (retval != 0) {
    printf("Warning: Cannot set MTU on port %u: %s\n", port, strerror(-retval));
    /* Continue anyway - some drivers don't support MTU change */
  } else {
    printf("Port %u MTU set to 1700\n", port);
  }

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

  // Compare the current destination MAC address to the broadcast address
  if (rte_is_broadcast_ether_addr(&eth_hdr->dst_addr) != 1) {
    // If it's not a broadcast address, update the destination MAC address
    rte_ether_addr_copy(&eth_hdr->dst_addr, &eth_hdr->src_addr);
    rte_ether_addr_copy(&mac_addr, &eth_hdr->dst_addr);
  }

  // Send the packets from the port no specified
  if (rte_eth_tx_burst(tx_port_id, 0, &mbuf, 1) == 0) {
    rte_pktmbuf_free(mbuf);
  }
  // Note: tx_burst takes ownership of mbuf on success, don't free here
}

// Static buffer to avoid malloc in hot path (max MTU 9000)
static __thread uint8_t tmp_payload_buffer[9000];

// Returns 0 on success, -1 on failure
int add_custom_header6(struct rte_mbuf *pkt) {

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

  // Use static buffer instead of malloc for performance
  if (payload_size > sizeof(tmp_payload_buffer)) {
    printf("ERROR: Packet payload too large: %zu bytes\n", payload_size);
    return -1; // Packet too large
  }

  // Check if we have enough tailroom for the extra headers
  size_t extra_headers_size = sizeof(struct ipv6_srh) + sizeof(struct hmac_tlv) + sizeof(struct pot_tlv);
  if (rte_pktmbuf_tailroom(pkt) < extra_headers_size) {
    printf("ERROR: Not enough tailroom for headers. Need %zu, have %u\n", 
           extra_headers_size, rte_pktmbuf_tailroom(pkt));
    return -1; // Not enough space
  }

  // save the payload which will be deleted and added later
  memcpy(tmp_payload_buffer, payload, payload_size);

  // Remove the payload
  rte_pktmbuf_trim(pkt, payload_size);

  // Add the custom headers in order and finally add the payload
  srh_hdr = (struct ipv6_srh *)rte_pktmbuf_append(pkt, sizeof(struct ipv6_srh));
  if (srh_hdr == NULL) {
    printf("ERROR: Failed to append SRH header\n");
    return -1;
  }
  hmac_hdr =
      (struct hmac_tlv *)rte_pktmbuf_append(pkt, sizeof(struct hmac_tlv));
  if (hmac_hdr == NULL) {
    printf("ERROR: Failed to append HMAC header\n");
    return -1;
  }
  pot_hdr = (struct pot_tlv *)rte_pktmbuf_append(pkt, sizeof(struct pot_tlv));
  if (pot_hdr == NULL) {
    printf("ERROR: Failed to append POT header\n");
    return -1;
  }
  payload = (uint8_t *)rte_pktmbuf_append(pkt, payload_size);
  if (payload == NULL) {
    printf("ERROR: Failed to append payload of size %zu\n", payload_size);
    return -1;
  }

  // Reinsert the payload
  memcpy(payload, tmp_payload_buffer, payload_size);

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

  // printf("Custom header added. Next Proto set to: %d, IPv6 Proto set to:
  // 43\n",
  //        original_proto);
  return 0;  // Success
}

void add_custom_header6_only_srh(struct rte_mbuf *pkt) {
  struct ipv6_srh *srh_hdr;
  struct hmac_tlv *hmac_hdr;
  struct pot_tlv *pot_hdr;
  struct rte_ether_hdr *eth_hdr_6 =
      rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
  struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr_6 + 1);
  uint8_t *payload = (uint8_t *)(ipv6_hdr + 1);

  // Assuming ip6 packets the size of ethernet header + ip6 header is 54 bytes
  size_t payload_size = rte_pktmbuf_pkt_len(pkt) - 54;

  // Use static buffer instead of malloc for performance
  if (payload_size > sizeof(tmp_payload_buffer)) {
    return; // Packet too large
  }

  // save the payload which will be deleted and added later
  memcpy(tmp_payload_buffer, payload, payload_size);

  // Remove the payload
  rte_pktmbuf_trim(pkt, payload_size);

  srh_hdr = (struct ipv6_srh *)rte_pktmbuf_append(pkt, sizeof(struct ipv6_srh));
  payload = (uint8_t *)rte_pktmbuf_append(pkt, payload_size);

  memcpy(payload, tmp_payload_buffer, payload_size);

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

// Optimized: prepare HMAC input without allocating crypto resources
static inline void prepare_hmac_input(
    uint8_t *src_addr,
    const struct ipv6_srh *srh,
    const struct hmac_tlv *hmac_tlv,
    uint8_t *input,
    size_t *input_len)
{
  size_t segment_list_len = sizeof(srh->segments);
  *input_len = 16 + 1 + 1 + 2 + 4 + segment_list_len;
  
  size_t offset = 0;
  memcpy(input + offset, src_addr, 16);
  offset += 16;
  input[offset++] = srh->last_entry;
  input[offset++] = srh->flags;
  input[offset++] = 0;
  input[offset++] = 0;
  memcpy(input + offset, &hmac_tlv->hmac_key_id, sizeof(hmac_tlv->hmac_key_id));
  offset += sizeof(hmac_tlv->hmac_key_id);
  memcpy(input + offset, srh->segments, segment_list_len);
}

// Single packet HMAC (fallback)
int calculate_hmac(uint8_t *src_addr,
                   const struct ipv6_srh *srh,
                   const struct hmac_tlv *hmac_tlv,
                   uint8_t *key,
                   size_t key_len,
                   uint8_t *hmac_out)
{
  uint8_t input[128];
  size_t input_len;
  prepare_hmac_input(src_addr, srh, hmac_tlv, input, &input_len);

  struct rte_crypto_op *op;
  struct rte_mbuf *m;

  if (rte_crypto_op_bulk_alloc(crypto_op_pool, RTE_CRYPTO_OP_TYPE_SYMMETRIC, &op, 1) == 0)
    return -1;

  m = rte_pktmbuf_alloc(crypto_mbuf_pool);
  if (m == NULL) {
    rte_crypto_op_free(op);
    return -1;
  }

  char *mbuf_data = rte_pktmbuf_append(m, input_len);
  if (mbuf_data == NULL) {
    rte_pktmbuf_free(m);
    rte_crypto_op_free(op);
    return -1;
  }
  memcpy(mbuf_data, input, input_len);

  op->sym->m_src = m;
  op->sym->auth.data.offset = 0;
  op->sym->auth.data.length = input_len;
  op->sym->auth.digest.data = hmac_out;
  op->sym->auth.digest.phys_addr = rte_mem_virt2iova(hmac_out);

  if (rte_crypto_op_attach_sym_session(op, hmac_session) < 0) {
    rte_pktmbuf_free(m);
    rte_crypto_op_free(op);
    return -1;
  }

  if (rte_cryptodev_enqueue_burst(cdev_id, 0, &op, 1) == 0) {
    rte_pktmbuf_free(m);
    rte_crypto_op_free(op);
    return -1;
  }

  struct rte_crypto_op *dequeued_op;
  uint16_t num_dequeued = 0;
  for (int retries = 0; num_dequeued == 0 && retries < 1000; retries++)
    num_dequeued = rte_cryptodev_dequeue_burst(cdev_id, 0, &dequeued_op, 1);

  if (num_dequeued == 0 || dequeued_op->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
    rte_pktmbuf_free(m);
    rte_crypto_op_free(op);
    return -1;
  }

  rte_pktmbuf_free(m);
  rte_crypto_op_free(dequeued_op);
  return 0;
}

// Calculates the PVF using the output of calulcate_hmac function with key
// k_hmac_ie

int generate_nonce(uint8_t nonce[NONCE_LENGTH]) {
  // Generate random nonce using rte_rand()
  for (int i = 0; i < NONCE_LENGTH; i++) {
    nonce[i] = (uint8_t)(rte_rand() & 0xFF);
  }
  // printf("Generated Nonce: ");
  // for (int i = 0; i < NONCE_LENGTH; i++) {
  //   printf("%02x", nonce[i]);
  // }
  // printf("\n");
  return 0;
}
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext) {
  struct rte_crypto_op *op;
  struct rte_mbuf *m;

  if (rte_crypto_op_bulk_alloc(crypto_op_pool, RTE_CRYPTO_OP_TYPE_SYMMETRIC, &op, 1) == 0)
    return -1;

  m = rte_pktmbuf_alloc(crypto_mbuf_pool);
  if (m == NULL) {
    rte_crypto_op_free(op);
    return -1;
  }

  char *mbuf_data = rte_pktmbuf_append(m, plaintext_len);
  if (mbuf_data == NULL) {
    rte_pktmbuf_free(m);
    rte_crypto_op_free(op);
    return -1;
  }
  memcpy(mbuf_data, plaintext, plaintext_len);

  op->sym->m_src = m;
  op->sym->cipher.data.offset = 0;
  op->sym->cipher.data.length = plaintext_len;

  uint8_t *iv_ptr = rte_crypto_op_ctod_offset(
      op, uint8_t *,
      offsetof(struct rte_crypto_op, sym) + sizeof(struct rte_crypto_sym_op));
  memcpy(iv_ptr, iv, NONCE_LENGTH);

  if (rte_crypto_op_attach_sym_session(op, cipher_session) < 0) {
    rte_pktmbuf_free(m);
    rte_crypto_op_free(op);
    return -1;
  }

  if (rte_cryptodev_enqueue_burst(cdev_id, 0, &op, 1) == 0) {
    rte_pktmbuf_free(m);
    rte_crypto_op_free(op);
    return -1;
  }

  struct rte_crypto_op *dequeued_op;
  uint16_t num_dequeued = 0;
  for (int retries = 0; num_dequeued == 0 && retries < 1000; retries++)
    num_dequeued = rte_cryptodev_dequeue_burst(cdev_id, 0, &dequeued_op, 1);

  if (num_dequeued == 0 || dequeued_op->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
    rte_pktmbuf_free(m);
    rte_crypto_op_free(op);
    return -1;
  }

  memcpy(ciphertext, rte_pktmbuf_mtod(m, uint8_t *), plaintext_len);
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
  // printf("\n----------Encrypting----------\n");

  // [FIX] Encrypt only ONCE since Controller decrypts only once
  // If Middlenode is in the path and decrypts, then we need 2 encryptions.
  // If Middlenode is bypassed, we need only 1 encryption.
  // Current topology: Creator -> Controller (no Middlenode processing)
  for (int i = 0; i < 1; i++) {
    // printf("---Iteration: %d---\n", i);
    // printf("original text is:\n");
    // for (int j = 0; j < HMAC_MAX_LENGTH; j++) {
    //   printf("%02x", hmac_out[j]);
    // }
    // printf("\n");

    int cipher_len =
        encrypt(hmac_out, HMAC_MAX_LENGTH, k_pot_in[i], nonce, ciphertext);
    if (cipher_len > 0) {
      // printf("Encryption successful, cipher_len=%d\n", cipher_len);
      memcpy(hmac_out, ciphertext, 32);
    } else {
      // printf("Encryption FAILED!\n");
    }
  }
}

int decrypt_pvf(uint8_t k_pot_in[SID_NO][HMAC_MAX_LENGTH], uint8_t *nonce,
                uint8_t pvf_out[32]) {
  // k_pot_in is a 2d array of strings holding statically allocated keys for the
  // nodes. In this proof of concept there is only one middle node and an egress
  // node so the shape is [2][key-length]
  uint8_t plaintext[128];
  int cipher_len = 32;
  // printf("\n----------Decrypting----------\n");
  for (int i = SID_NO - 1; i >= 0; i--) {
    // printf("---Iteration: %d---\n", i);
    int dec_len = decrypt(pvf_out, cipher_len, k_pot_in[i], nonce, plaintext);
    // printf("Dec len %d\n", dec_len);
    // printf("original text is:\n");
    // for (int j = 0; j < HMAC_MAX_LENGTH; j++) {
    //   printf("%02x", pvf_out[j]);
    // }
    // printf("\n");
    memcpy(pvf_out, plaintext, 32);
    // printf("Decrypted text is : \n");
    // for (int j = 0; j < dec_len; j++) {
    //   printf("%02x ", pvf_out[j]);
    //   if ((j + 1) % 16 == 0)
    //     printf("\n");
    // }
    // printf("\n");
  }
  return 0;
}

// Structure to hold packet processing context for batch crypto
struct pkt_crypto_ctx {
  struct rte_mbuf *mbuf;
  struct ipv6_srh *srh;
  struct hmac_tlv *hmac;
  struct pot_tlv *pot;
  uint8_t hmac_input[128];
  size_t hmac_input_len;
  uint8_t hmac_out[HMAC_MAX_LENGTH];
  uint8_t nonce[NONCE_LENGTH];
  uint8_t k_pot_in[SID_NO][HMAC_MAX_LENGTH];
  int valid;
};

// Pre-defined IPv6 addresses for fast binary comparison
static const uint8_t addr_server_ns[16] = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00,
                                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
static const uint8_t addr_server_old[16] = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x04, 0x00, 0x00,
                                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};

int l_loop1(uint16_t rx_port_id, uint16_t tx_port_id) {
  struct rte_ether_addr middle_node_mac_addr = {
      {0x08, 0x00, 0x27, 0xC6, 0x79, 0x2A}};
  
  // Pre-allocated crypto operations and mbufs for batch processing
  struct rte_crypto_op *hmac_ops[BURST_SIZE];
  struct rte_crypto_op *cipher_ops[BURST_SIZE];
  struct rte_mbuf *crypto_mbufs[BURST_SIZE * 2];
  struct pkt_crypto_ctx ctx[BURST_SIZE];
  
  static const uint8_t k_hmac_ie[] = "my-hmac-key-for-pvf-calculation";
  static const size_t key_len = 31;

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
        rte_pktmbuf_free(mbuf);
        break;
      case RTE_ETHER_TYPE_IPV6:
        switch (operation_bypass_bit) {
        case 0: {
          // Add custom headers
          if (add_custom_header6(mbuf) != 0) {
            rte_pktmbuf_free(mbuf);
            break;
          }

          // Get header pointers
          struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
          struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
          struct ipv6_srh *srh = (struct ipv6_srh *)(ipv6_hdr + 1);
          struct hmac_tlv *hmac = (struct hmac_tlv *)(srh + 1);
          struct pot_tlv *pot = (struct pot_tlv *)(hmac + 1);

          uint8_t hmac_out[HMAC_MAX_LENGTH];
          uint8_t nonce[NONCE_LENGTH];
          uint8_t k_pot_in[SID_NO][HMAC_MAX_LENGTH];
          memset(k_pot_in, 0, sizeof(k_pot_in));

          // Fast binary comparison instead of inet_ntop + strncmp
          if (memcmp(&ipv6_hdr->dst_addr, addr_server_ns, 16) == 0) {
            memcpy(k_pot_in[0], "eerreerreerreerreerreerreerreer", 31);
            memcpy(k_pot_in[1], "eerreerreerreerreerreerreerreer", 31);
          } else if (memcmp(&ipv6_hdr->dst_addr, addr_server_old, 16) == 0) {
            memcpy(k_pot_in[0], "eerreerreerreerreerreerreerreer", 31);
          } else {
            // Default key for unknown destinations
            memcpy(k_pot_in[0], "eerreerreerreerreerreerreerreer", 31);
          }

          // Compute HMAC
          if (calculate_hmac(ipv6_hdr->src_addr, srh, hmac, 
                             (uint8_t*)k_hmac_ie, key_len, hmac_out) == 0) {
            memcpy(hmac->hmac_value, hmac_out, 32);
          }

          // Generate nonce and encrypt PVF
          generate_nonce(nonce);
          encrypt_pvf(k_pot_in, nonce, hmac_out);
          memcpy(pot->encrypted_hmac, hmac_out, 32);
          memcpy(pot->nonce, nonce, 16);

          send_packet_to(middle_node_mac_addr, mbuf, tx_port_id);
          break;
        }
        case 1:
          send_packet_to(middle_node_mac_addr, mbuf, tx_port_id);
          break;
        case 2:
          add_custom_header6_only_srh(mbuf);
          // for iperf testing swap the mac address (normally the scapy
          // generated packets have broadcast dest mac)
          send_packet_to(middle_node_mac_addr, mbuf, tx_port_id);
          break;

        default:
          // Free mbuf only for unhandled cases
          rte_pktmbuf_free(mbuf);
          break;
        }
        // Note: mbuf is freed by send_packet_to or in default case
      }
    }
  }
}

void l_loop2(uint16_t rx_port_id, uint16_t tx_port_id) {
  struct rte_ether_addr traffic_mac_addr = {
      {0x08, 0x00, 0x27, 0x0F, 0xAC, 0x33}};
  
  // Batch TX buffer
  struct rte_mbuf *tx_bufs[BURST_SIZE];
  uint16_t tx_count = 0;
  
  for (;;) {
    struct rte_mbuf *bufs[BURST_SIZE];
    uint16_t nb_rx = rte_eth_rx_burst(rx_port_id, 0, bufs, BURST_SIZE);

    if (unlikely(nb_rx == 0)) {
      // Flush any pending TX packets
      if (tx_count > 0) {
        uint16_t sent = rte_eth_tx_burst(tx_port_id, 0, tx_bufs, tx_count);
        for (uint16_t j = sent; j < tx_count; j++)
          rte_pktmbuf_free(tx_bufs[j]);
        tx_count = 0;
      }
      continue;
    }

    for (int i = 0; i < nb_rx; i++) {
      struct rte_mbuf *mbuf = bufs[i];
      struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

      if (likely(rte_be_to_cpu_16(eth_hdr->ether_type) == RTE_ETHER_TYPE_IPV6)) {
        struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
        
        // Fast binary comparison instead of inet_ntop + strncmp
        if (memcmp(&ipv6_hdr->src_addr, addr_server_ns, 16) == 0) {
          // Update MAC and add to TX batch
          rte_ether_addr_copy(&eth_hdr->dst_addr, &eth_hdr->src_addr);
          rte_ether_addr_copy(&traffic_mac_addr, &eth_hdr->dst_addr);
          tx_bufs[tx_count++] = mbuf;
        } else {
          rte_pktmbuf_free(mbuf);
        }
      } else {
        rte_pktmbuf_free(mbuf);
      }
    }
    
    // Batch TX - send all at once
    if (tx_count > 0) {
      uint16_t sent = rte_eth_tx_burst(tx_port_id, 0, tx_bufs, tx_count);
      for (uint16_t j = sent; j < tx_count; j++)
        rte_pktmbuf_free(tx_bufs[j]);
      tx_count = 0;
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
  lcore_id = rte_get_next_lcore(-1, 1, 0);
  rte_eal_remote_launch(lcore_main_forward2, (void *)ports, lcore_id);
  lcore_main_forward((void *)ports);
  // rte_eal_mp_wait_lcore();  cd /home/melih/Desktop/dpdk-app/dpdk-app-master
  return 0;
}