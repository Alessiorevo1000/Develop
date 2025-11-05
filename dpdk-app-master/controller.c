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

#define RX_RING_SIZE 2048
#define TX_RING_SIZE 2048
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 256
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
    printf("Error sending packet\n");
    rte_pktmbuf_free(mbuf);
  } else {
    printf("IPV6 packet sent\n");
  }
  rte_pktmbuf_free(mbuf);
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
  // k_pot_in is a 2d array of strings holding statically allocated keys for the
  // nodes. In this proof of concept there is only one middle node and an egress
  // node so the shape is [2][key-length]
  uint8_t plaintext[128];
  int cipher_len = 32;
  printf("\n----------Decrypting----------\n");
  int dec_len = decrypt(pvf_out, cipher_len, k_pot_in, nonce, plaintext);
  printf("Dec len %d\n", dec_len);
  printf("original text is:\n");
  for (int j = 0; j < 32; j++) {
    printf("%02x", pvf_out[j]);
  }
  printf("\n");
  memcpy(pvf_out, plaintext, 32);
  printf("Decrypted text is : \n");
  BIO_dump_fp(stdout, (const char *)pvf_out, dec_len);
}

int compare_hmac(struct hmac_tlv *hmac, uint8_t *hmac_out,
                 struct rte_mbuf *mbuf) {
  if (strncmp(hmac->hmac_value, hmac_out, 32) != 0) {
    printf("The decrypted hmac is not the same as the computed hmac\n");
    printf("dropping the packet\n");
    rte_pktmbuf_free(mbuf);
    return 0;
  } else {
    printf("The transit of the packet is verified\n");
    // forward it to the tap interface so iperf can catch it
    return 1;
  }
}

int process_ip6_with_srh(struct rte_ether_hdr *eth_hdr, struct rte_mbuf *mbuf,
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
    uint8_t k_pot_in[32] = "qqwwqqwwqqwwqqwwqqwwqqwwqqwwqqw";
    uint8_t k_hmac_ie[] = "my-hmac-key-for-pvf-calculation";

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
    uint8_t hmac_out[32];
    memcpy(hmac_out, pot->encrypted_hmac, 32);
    decrypt_pvf(k_pot_in, pot->nonce, hmac_out);

    // update the pot header pvf field
    memcpy(pot->encrypted_hmac, hmac_out, 32);

    int retval;
    retval = compare_hmac(hmac, hmac_out, mbuf);

    fflush(stdout);
    return retval;
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

void remove_headers(struct rte_mbuf *pkt) {

  struct rte_ether_hdr *eth_hdr_6 =
      rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
  struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr_6 + 1);
  struct ipv6_srh *srh = (struct ipv6_srh *)(ipv6_hdr + 1);
  struct hmac_tlv *hmac = (struct hmac_tlv *)(srh + 1);
  struct pot_tlv *pot = (struct pot_tlv *)(hmac + 1);
  uint8_t *payload = (uint8_t *)(pot + 1); // this also cantains l4 header

  // reinsert the initial ip6 nexr header for iperf testing the insertion is
  // manual in this case is 6 ipv6_hdr->proto = 17;

  printf("packet length: %u\n", rte_pktmbuf_pkt_len(pkt));
  // Assuming ip6 packets the size of ethernet header + ip6 header is 54 bytes
  // plus the headers between
  size_t payload_size = rte_pktmbuf_pkt_len(pkt) -
                        (54 + sizeof(struct ipv6_srh) +
                         sizeof(struct hmac_tlv) + sizeof(struct pot_tlv));

  printf("Payload size: %lu\n", payload_size);
  uint8_t *tmp_payload = (uint8_t *)malloc(payload_size);
  if (tmp_payload == NULL) {
    printf("malloc failed\n");
  }
  // save the payload which will be deleted and added later
  memcpy(tmp_payload, payload, payload_size);

  // remove headers from the tail
  rte_pktmbuf_trim(pkt, payload_size);
  rte_pktmbuf_trim(pkt, sizeof(struct pot_tlv));
  rte_pktmbuf_trim(pkt, sizeof(struct hmac_tlv));
  rte_pktmbuf_trim(pkt, sizeof(struct ipv6_srh));

  payload = (uint8_t *)rte_pktmbuf_append(pkt, payload_size);
  memcpy(payload, tmp_payload, payload_size);
  free(tmp_payload);
}

void remove_headers_only_srh(struct rte_mbuf *pkt) {
  struct rte_ether_hdr *eth_hdr_6 =
      rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
  struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr_6 + 1);
  struct ipv6_srh *srh = (struct ipv6_srh *)(ipv6_hdr + 1);
  uint8_t *payload = (uint8_t *)(srh + 1); // this also cantains l4 header

  printf("packet length: %u\n", rte_pktmbuf_pkt_len(pkt));
  // Assuming ip6 packets the size of ethernet header + ip6 header is 54 bytes
  // plus the headers between
  size_t payload_size =
      rte_pktmbuf_pkt_len(pkt) - (54 + sizeof(struct ipv6_srh));

  printf("Payload size: %lu\n", payload_size);
  uint8_t *tmp_payload = (uint8_t *)malloc(payload_size);
  if (tmp_payload == NULL) {
    printf("malloc failed\n");
  }
  // save the payload which will be deleted and added later
  memcpy(tmp_payload, payload, payload_size);

  // remove headers from the tail
  rte_pktmbuf_trim(pkt, payload_size);
  rte_pktmbuf_trim(pkt, sizeof(struct ipv6_srh));

  payload = (uint8_t *)rte_pktmbuf_append(pkt, payload_size);
  memcpy(payload, tmp_payload, payload_size);
  free(tmp_payload);
}

void l_loop1(uint16_t port_id, uint16_t tap_port_id) {
  struct rte_ether_addr tap_mac_addr = {
      {0x08, 0x00, 0x27, 0x7D, 0xDD, 0x01}}; // mac of end node (new added wm)
  printf("Capturing packets on port %d...\n", port_id);

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

      switch (rte_be_to_cpu_16(eth_hdr->ether_type)) {
      case RTE_ETHER_TYPE_IPV4:
        break;
      case RTE_ETHER_TYPE_IPV6:

        switch (operation_bypass_bit) {
        case 0:
          int retval;
          retval = process_ip6_with_srh(eth_hdr, mbuf, i);
          // send the packet to eggress node
          if (retval == 1) {
            remove_headers(mbuf);
            send_packet_to(tap_mac_addr, mbuf, tap_port_id);
            /*
            if (rte_eth_tx_burst(tap_port_id, 0, &mbuf, 1) == 0) {
              printf("Error sending packet\n");
              rte_pktmbuf_free(mbuf);
            } else {
              printf("IPV6 packet sent\n");
            }
            rte_pktmbuf_free(mbuf);
            */
          }
          printf("\n###########################################################"
                 "################\n");
          break;
        case 1:
          printf("All operations are bypassed. \n");
          send_packet_to(tap_mac_addr, mbuf, tap_port_id);
          /*
          if (rte_eth_tx_burst(tap_port_id, 0, &mbuf, 1) == 0) {
            printf("Error sending packet\n");
            rte_pktmbuf_free(mbuf);
          } else {
            printf("IPV6 packet sent\n");
          }
          rte_pktmbuf_free(mbuf);
          */
          break;

        case 2:
          remove_headers_only_srh(mbuf);
          send_packet_to(tap_mac_addr, mbuf, tap_port_id);
          /*
          if (rte_eth_tx_burst(tap_port_id, 0, &mbuf, 1) == 0) {
            printf("Error sending packet\n");
            rte_pktmbuf_free(mbuf);
          } else {
            printf("IPV6 packet sent\n");
          }
          rte_pktmbuf_free(mbuf);
          */
          break;
        default:
          break;
        }

      default:
        break;
      }
    }
  }
}

void l_loop2(uint16_t port_id, uint16_t tap_port_id) {
  unsigned lcore_id;
  lcore_id = rte_lcore_id();
  printf("hello from core %u\n", lcore_id);
  printf("Capturing packets on port %d...\n", port_id);
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

      switch (rte_be_to_cpu_16(eth_hdr->ether_type)) {
      case RTE_ETHER_TYPE_IPV4:
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
          // tx port of traffic generator node packet goes D to C
          // (A <--> B <--> C <--> D)
          send_packet_to(middle_mac_addr, mbuf, tap_port_id);
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
  // lcore_id = rte_get_next_lcore(-1, 1, 0);
  // rte_eal_remote_launch(lcore_main_forward, (void *)ports, lcore_id);
  lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
  // rte_eal_remote_launch(lcore_main_forward2, (void *)ports, lcore_id);
  lcore_main_forward((void *)ports);
  // rte_eal_mp_wait_lcore();

  return 0;
}
