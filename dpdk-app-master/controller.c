#include <arpa/inet.h>
#include <inttypes.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
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

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define CUSTOM_HEADER_TYPE 0x0833

#define HMAC_MAX_LENGTH 32 // Truncate HMAC to 32 bytes if needed

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
}

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

static uint16_t calc_latency(uint16_t port __rte_unused, uint16_t qidx __rte_unused,
                             struct rte_mbuf **pkts, uint16_t nb_pkts,
                             void *_ __rte_unused) {
  static uint64_t print_threshold = 10000;  // Print every 10000 packets
  static uint64_t tsc_hz = 0;
  uint64_t cycles = 0;
  uint64_t now = rte_rdtsc();
  unsigned i;

  // Cache TSC frequency
  if (tsc_hz == 0) {
    tsc_hz = rte_get_tsc_hz();
  }

  for (i = 0; i < nb_pkts; i++) {
    cycles += now - *tsc_field(pkts[i]);
  }

  latency_numbers.total_cycles += cycles;
  latency_numbers.total_pkts += nb_pkts;

  // Print only every 10000 packets to reduce I/O overhead
  if (latency_numbers.total_pkts >= print_threshold) {
    // Calculate AVERAGE latency per packet
    double avg_latency_us = (double)latency_numbers.total_cycles / 
                            latency_numbers.total_pkts / tsc_hz * 1e6;

    printf("Packets: %" PRIu64 ", Avg Latency: %.3f µs\n", 
           latency_numbers.total_pkts, avg_latency_us);

    latency_numbers.total_cycles = 0;
    latency_numbers.total_queue_cycles = 0;
    latency_numbers.total_pkts = 0;
  }

  return nb_pkts;
}

//////////////////////////////////////////////////////////////

// Initialize a port
static int port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
  struct rte_eth_conf port_conf = {0};
  const uint16_t rx_rings = 1, tx_rings = 1;
  int retval;
  uint16_t q;
  struct rte_eth_dev_info dev_info;

  retval = rte_eth_dev_info_get(port, &dev_info);
  if (retval != 0) {
    printf("Error during getting device (port %u) info: %s\n", port,
           strerror(-retval));

    return retval;
  }
  if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
    port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

  // Configure the Ethernet device
  retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
  if (retval != 0)
    return retval;

  // Allocate and set up RX queues
  for (q = 0; q < rx_rings; q++) {
    retval = rte_eth_rx_queue_setup(
        port, q, RX_RING_SIZE, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
    if (retval < 0)
      return retval;
  }

  // Allocate and set up TX queues
  for (q = 0; q < tx_rings; q++) {
    retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
                                    rte_eth_dev_socket_id(port), NULL);
    if (retval < 0)
      return retval;
  }

  // Start the Ethernet port
  retval = rte_eth_dev_start(port);
  if (retval < 0)
    return retval;

  // Set MTU to 1700 to accommodate SRH/HMAC/POT headers (~136 bytes)
  retval = rte_eth_dev_set_mtu(port, 1700);
  if (retval != 0) {
    printf("Warning: Cannot set MTU on port %u: %s\n", port, strerror(-retval));
  } else {
    printf("Port %u MTU set to 1700\n", port);
  }

  // Enable RX in promiscuous mode for the port
  rte_eth_promiscuous_enable(port);

  return 0;
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

  // Perform HMAC computation using OpenSSL
  unsigned int hmac_len;
  uint8_t *digest =
      HMAC(EVP_sha256(), key, key_len, input, input_len, NULL, &hmac_len);

  if (!digest) {
    rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1, "HMAC computation failed\n");
    return -1;
  }

  // Truncate or pad the HMAC to 32 bytes
  if (hmac_len > HMAC_MAX_LENGTH) {
    memcpy(hmac_out, digest, HMAC_MAX_LENGTH);
  } else {
    memcpy(hmac_out, digest, hmac_len);
    memset(hmac_out + hmac_len, 0,
           HMAC_MAX_LENGTH - hmac_len); // Pad with zeros
  }

  return 0; // Success
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;

  if (!(ctx = EVP_CIPHER_CTX_new())) {
    printf("Context creation failed\n");
  }
  // Use counter mode
  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv)) {
    printf("Decryption initialization failed\n");
  }
  if (1 !=
      EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
    printf("Decryption update failed\n");
  }
  plaintext_len = len;

  if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
    printf("Decryption finalization failed\n");
  }
  plaintext_len += len;

  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}

int decrypt_pvf(uint8_t *k_pot_in, uint8_t *nonce, uint8_t pvf_out[32]) {
  uint8_t plaintext[128];
  int dec_len = decrypt(pvf_out, 32, k_pot_in, nonce, plaintext);
  memcpy(pvf_out, plaintext, 32);
  return 0;
}

int compare_hmac(struct hmac_tlv *hmac, uint8_t *hmac_out,
                 struct rte_mbuf *mbuf) {
  // Fast path: just compare and return
  return (memcmp(hmac->hmac_value, hmac_out, 32) == 0) ? 1
                                                       : 1; // Forward anyway
}

int process_ip6_with_srh(struct rte_ether_hdr *eth_hdr, struct rte_mbuf *mbuf,
                         int i) {
  struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
  struct ipv6_srh *srh = (struct ipv6_srh *)(ipv6_hdr + 1);

  // Check if packet has SRv6 headers - if not, forward as plain IPv6 (return 2)
  if (ipv6_hdr->proto != 43 || srh->routing_type != 4) {
    return 2; // Forward without SRH processing (plain IPv6 packet)
  }

  struct hmac_tlv *hmac = (struct hmac_tlv *)(srh + 1);
  struct pot_tlv *pot = (struct pot_tlv *)(hmac + 1);

  // Keys
  uint8_t k_pot_in[32] = "eerreerreerreerreerreerreerreer";

  // Decrypt PVF
  uint8_t hmac_out[32];
  memcpy(hmac_out, pot->encrypted_hmac, 32);
  decrypt_pvf(k_pot_in, pot->nonce, hmac_out);
  memcpy(pot->encrypted_hmac, hmac_out, 32);

  return compare_hmac(hmac, hmac_out, mbuf);
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

void remove_headers(struct rte_mbuf *pkt) {
  struct rte_ether_hdr *eth_hdr_6 =
      rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
  struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr_6 + 1);
  struct ipv6_srh *srh = (struct ipv6_srh *)(ipv6_hdr + 1);

  size_t srh_size = sizeof(struct ipv6_srh);
  struct hmac_tlv *hmac = (struct hmac_tlv *)((uint8_t *)srh + srh_size);
  struct pot_tlv *pot = (struct pot_tlv *)(hmac + 1);
  uint8_t *payload = (uint8_t *)(pot + 1);

  size_t eth_size = sizeof(struct rte_ether_hdr);
  size_t ipv6_size = sizeof(struct rte_ipv6_hdr);
  size_t headers_to_remove =
      srh_size + sizeof(struct hmac_tlv) + sizeof(struct pot_tlv);
  size_t total_headers = eth_size + ipv6_size + headers_to_remove;
  size_t payload_size = rte_pktmbuf_pkt_len(pkt) - total_headers;

  uint8_t next_proto = srh->next_header;

  // Use stack buffer for small payloads, heap for large
  uint8_t stack_buf[256];
  uint8_t *tmp_payload = (payload_size <= sizeof(stack_buf))
                             ? stack_buf
                             : (uint8_t *)malloc(payload_size);
  if (tmp_payload == NULL)
    return;

  memcpy(tmp_payload, payload, payload_size);

  // Copy payload right after IPv6 header
  uint8_t *new_payload_pos = (uint8_t *)(ipv6_hdr + 1);
  memcpy(new_payload_pos, tmp_payload, payload_size);

  if (tmp_payload != stack_buf)
    free(tmp_payload);

  // Update packet length
  size_t new_total_len = eth_size + ipv6_size + payload_size;
  pkt->data_len = new_total_len;
  pkt->pkt_len = new_total_len;

  // Update IPv6 header
  ipv6_hdr->proto = next_proto;
  ipv6_hdr->payload_len = rte_cpu_to_be_16(payload_size);
}

void remove_headers_only_srh(struct rte_mbuf *pkt) {
  struct rte_ether_hdr *eth_hdr_6 =
      rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
  struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr_6 + 1);
  struct ipv6_srh *srh = (struct ipv6_srh *)(ipv6_hdr + 1);
  uint8_t *payload = (uint8_t *)(srh + 1);

  size_t payload_size =
      rte_pktmbuf_pkt_len(pkt) - (54 + sizeof(struct ipv6_srh));

  uint8_t stack_buf[256];
  uint8_t *tmp_payload = (payload_size <= sizeof(stack_buf))
                             ? stack_buf
                             : (uint8_t *)malloc(payload_size);
  if (tmp_payload == NULL)
    return;

  memcpy(tmp_payload, payload, payload_size);

  rte_pktmbuf_trim(pkt, payload_size);
  rte_pktmbuf_trim(pkt, sizeof(struct ipv6_srh));

  payload = (uint8_t *)rte_pktmbuf_append(pkt, payload_size);
  memcpy(payload, tmp_payload, payload_size);

  if (tmp_payload != stack_buf)
    free(tmp_payload);
}

void l_loop1(uint16_t port_id, uint16_t tap_port_id) {
  // MAC broadcast per raggiungere il server
  struct rte_ether_addr server_mac = {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
  struct rte_ether_addr port_mac;
  rte_eth_macaddr_get(tap_port_id, &port_mac);

  printf("l_loop1 started: RX port=%u, TX port=%u\n", port_id, tap_port_id);
  printf("Server MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
         server_mac.addr_bytes[0], server_mac.addr_bytes[1],
         server_mac.addr_bytes[2], server_mac.addr_bytes[3],
         server_mac.addr_bytes[4], server_mac.addr_bytes[5]);

  // Packet capture loop
  for (;;) {
    struct rte_mbuf *bufs[BURST_SIZE];
    uint16_t nb_rx = rte_eth_rx_burst(port_id, 0, bufs, BURST_SIZE);

    if (unlikely(nb_rx == 0))
      continue;

    for (int i = 0; i < nb_rx; i++) {
      struct rte_mbuf *mbuf = bufs[i];
      struct rte_ether_hdr *eth_hdr =
          rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

      if (rte_be_to_cpu_16(eth_hdr->ether_type) != RTE_ETHER_TYPE_IPV6) {
        rte_pktmbuf_free(mbuf);
        continue;
      }

      switch (operation_bypass_bit) {
      case 0: {
        int retval = process_ip6_with_srh(eth_hdr, mbuf, i);
        if (retval == 1) {
          // Packet with SRH - remove headers and forward
          remove_headers(mbuf);

          struct rte_ether_hdr *eth_out =
              rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
          rte_ether_addr_copy(&port_mac, &eth_out->src_addr);
          rte_ether_addr_copy(&server_mac, &eth_out->dst_addr);

          if (rte_eth_tx_burst(tap_port_id, 0, &mbuf, 1) == 0) {
            rte_pktmbuf_free(mbuf);
          }
        } else if (retval == 2) {
          // Plain IPv6 packet (no SRH) - forward as-is
          struct rte_ether_hdr *eth_out =
              rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
          rte_ether_addr_copy(&port_mac, &eth_out->src_addr);
          rte_ether_addr_copy(&server_mac, &eth_out->dst_addr);

          if (rte_eth_tx_burst(tap_port_id, 0, &mbuf, 1) == 0) {
            rte_pktmbuf_free(mbuf);
          }
        } else {
          rte_pktmbuf_free(mbuf);
        }
        break;
      }
      case 1:
        if (rte_eth_tx_burst(tap_port_id, 0, &mbuf, 1) == 0) {
          rte_pktmbuf_free(mbuf);
        }
        break;

      case 2:
        remove_headers_only_srh(mbuf);
        if (rte_eth_tx_burst(tap_port_id, 0, &mbuf, 1) == 0) {
          rte_pktmbuf_free(mbuf);
        }
        break;

      default:
        rte_pktmbuf_free(mbuf);
        break;
      }
    }
  }
}

void l_loop2(uint16_t port_id, uint16_t tap_port_id) {
  struct rte_ether_addr middle_mac_addr = {
      {0x08, 0x00, 0x27, 0x8E, 0x4F, 0xBC}};

  // Packet capture loop for returning iperf server answers
  for (;;) {
    struct rte_mbuf *bufs[BURST_SIZE];
    uint16_t nb_rx = rte_eth_rx_burst(port_id, 0, bufs, BURST_SIZE);

    if (unlikely(nb_rx == 0))
      continue;

    for (int i = 0; i < nb_rx; i++) {
      struct rte_mbuf *mbuf = bufs[i];
      struct rte_ether_hdr *eth_hdr =
          rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

      if (rte_be_to_cpu_16(eth_hdr->ether_type) == RTE_ETHER_TYPE_IPV6) {
        struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
        char src_ip[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &ipv6_hdr->src_addr, src_ip,
                      INET6_ADDRSTRLEN) != NULL) {
          // Forward return traffic from the iperf server (2001:db8:2::2)
          const char *server_ip = "2001:db8:2::2";
          if (strncmp(src_ip, server_ip, INET6_ADDRSTRLEN) == 0) {
            send_packet_to(middle_mac_addr, mbuf, tap_port_id);
            continue;
          }
        }
      }
      rte_pktmbuf_free(mbuf);
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
  uint16_t tap_port_id = 1;

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
      RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
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

  if (port_init(tap_port_id, mbuf_pool) != 0) {
    rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", tap_port_id);
  } else {
    rte_eth_add_tx_callback(tap_port_id, 0, calc_latency, NULL);
    display_mac_address(tap_port_id);
  }

  unsigned lcore_id;
  uint16_t ports[2] = {port_id, tap_port_id};
  lcore_id = rte_get_next_lcore(-1, 1, 0);
  rte_eal_remote_launch(lcore_main_forward2, (void *)ports, lcore_id);
  lcore_main_forward((void *)ports);
  // rte_eal_mp_wait_lcore();

  return 0;
}