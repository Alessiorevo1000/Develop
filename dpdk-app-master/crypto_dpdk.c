// DPDK Cryptodev Implementation
// Hardware-accelerated crypto operations for SRv6 POT

#include "crypto_dpdk.h"
#include <rte_cryptodev.h>
#include <rte_crypto.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <stdio.h>
#include <string.h>

#define CRYPTO_DEV_ID 0
#define NUM_CRYPTO_OPS 512
#define SESSION_POOL_CACHE_SIZE 0
#define CRYPTO_OP_POOL_SIZE 16384
#define IV_OFFSET 0

// Global structures
static struct rte_mempool *crypto_op_pool = NULL;
static struct rte_mempool *session_pool = NULL;
static struct rte_mempool *session_priv_pool = NULL;
static struct rte_mempool *crypto_mbuf_pool = NULL;
static uint8_t crypto_dev_id = CRYPTO_DEV_ID;
static int crypto_initialized = 0;

/**
 * Initialize DPDK cryptodev device
 */
int crypto_dpdk_init(void) {
    struct rte_cryptodev_config config;
    struct rte_cryptodev_qp_conf qp_conf;
    struct rte_cryptodev_info dev_info;
    uint32_t socket_id = rte_socket_id();
    
    if (crypto_initialized) {
        printf("Cryptodev already initialized\n");
        return 0;
    }
    
    // Check if crypto device is available
    if (rte_cryptodev_count() == 0) {
        printf("WARNING: No crypto devices available\n");
        printf("Use --vdev crypto_aesni_mb or --vdev crypto_openssl to enable software crypto\n");
        printf("Example: ./app --vdev crypto_aesni_mb -- <args>\n");
        return -1;
    }
    
    printf("Number of crypto devices available: %u\n", rte_cryptodev_count());
    
    // Get device info
    rte_cryptodev_info_get(crypto_dev_id, &dev_info);
    printf("Crypto device %u: %s\n", crypto_dev_id, dev_info.driver_name);
    printf("Max number of queue pairs: %u\n", dev_info.max_nb_queue_pairs);
    
    // Create crypto operation pool
    crypto_op_pool = rte_crypto_op_pool_create(
        "crypto_op_pool",
        RTE_CRYPTO_OP_TYPE_SYMMETRIC,
        CRYPTO_OP_POOL_SIZE,
        128,
        sizeof(struct rte_crypto_sym_xform),
        socket_id
    );
    
    if (crypto_op_pool == NULL) {
        printf("Failed to create crypto operation pool\n");
        return -1;
    }
    
    // Create session pool
    session_pool = rte_cryptodev_sym_session_pool_create(
        "session_pool",
        NUM_CRYPTO_OPS,
        0,
        SESSION_POOL_CACHE_SIZE,
        0,
        socket_id
    );
    
    if (session_pool == NULL) {
        printf("Failed to create session pool\n");
        return -1;
    }
    
    // Create session private data pool
    session_priv_pool = rte_mempool_create(
        "session_priv_pool",
        NUM_CRYPTO_OPS,
        rte_cryptodev_sym_get_private_session_size(crypto_dev_id),
        SESSION_POOL_CACHE_SIZE,
        0,
        NULL,
        NULL,
        NULL,
        NULL,
        socket_id,
        0
    );
    
    if (session_priv_pool == NULL) {
        printf("Failed to create session private pool\n");
        return -1;
    }
    
    // Configure crypto device
    config.socket_id = socket_id;
    config.nb_queue_pairs = 1;
    config.ff_disable = 0;
    
    if (rte_cryptodev_configure(crypto_dev_id, &config) < 0) {
        printf("Failed to configure crypto device\n");
        return -1;
    }
    
    // Configure queue pair
    qp_conf.nb_descriptors = NUM_CRYPTO_OPS;
    qp_conf.mp_session = session_pool;
    
    if (rte_cryptodev_queue_pair_setup(crypto_dev_id, 0, &qp_conf, socket_id) < 0) {
        printf("Failed to setup queue pair\n");
        return -1;
    }
    
    // Start crypto device
    if (rte_cryptodev_start(crypto_dev_id) < 0) {
        printf("Failed to start crypto device\n");
        return -1;
    }
    
    crypto_initialized = 1;
    printf("✓ Crypto device initialized successfully\n");
    return 0;
}

/**
 * Set the mbuf pool for crypto operations
 */
void crypto_dpdk_set_mbuf_pool(struct rte_mempool *pool) {
    crypto_mbuf_pool = pool;
}

/**
 * Perform AES-256-CTR encryption
 */
int crypto_dpdk_encrypt(const uint8_t *plaintext, int plaintext_len,
                        const uint8_t *key, const uint8_t *iv, uint8_t *ciphertext) {
    struct rte_crypto_op *op;
    struct rte_crypto_sym_op *sym_op;
    struct rte_mbuf *mbuf;
    void *session;
    struct rte_crypto_sym_xform cipher_xform;
    int ret;
    
    if (!crypto_initialized || crypto_mbuf_pool == NULL) {
        printf("ERROR: Crypto not initialized or mbuf pool not set\n");
        return -1;
    }
    
    // Setup cipher transform
    memset(&cipher_xform, 0, sizeof(cipher_xform));
    cipher_xform.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
    cipher_xform.next = NULL;
    cipher_xform.cipher.algo = RTE_CRYPTO_CIPHER_AES_CTR;
    cipher_xform.cipher.op = RTE_CRYPTO_CIPHER_OP_ENCRYPT;
    cipher_xform.cipher.key.data = (uint8_t *)key;
    cipher_xform.cipher.key.length = 32; // AES-256
    cipher_xform.cipher.iv.offset = IV_OFFSET;
    cipher_xform.cipher.iv.length = 16;
    
    // Create session
    session = rte_cryptodev_sym_session_create(crypto_dev_id, &cipher_xform, session_pool);
    if (session == NULL) {
        printf("Failed to create encryption session\n");
        return -1;
    }
    
    // Allocate crypto operation
    op = rte_crypto_op_alloc(crypto_op_pool, RTE_CRYPTO_OP_TYPE_SYMMETRIC);
    if (op == NULL) {
        printf("Failed to allocate crypto operation\n");
        rte_cryptodev_sym_session_free(crypto_dev_id, session);
        return -1;
    }
    
    // Allocate mbuf
    mbuf = rte_pktmbuf_alloc(crypto_mbuf_pool);
    if (mbuf == NULL) {
        printf("Failed to allocate mbuf\n");
        rte_crypto_op_free(op);
        rte_cryptodev_sym_session_free(crypto_dev_id, session);
        return -1;
    }
    
    // Append IV + data to mbuf
    uint8_t *data = (uint8_t *)rte_pktmbuf_append(mbuf, 16 + plaintext_len);
    if (data == NULL) {
        printf("Failed to append data to mbuf\n");
        rte_pktmbuf_free(mbuf);
        rte_crypto_op_free(op);
        rte_cryptodev_sym_session_free(crypto_dev_id, session);
        return -1;
    }
    
    // Copy IV and plaintext
    memcpy(data, iv, 16);
    memcpy(data + 16, plaintext, plaintext_len);
    
    // Setup symmetric operation
    sym_op = op->sym;
    sym_op->m_src = mbuf;
    sym_op->m_dst = NULL; // In-place operation
    
    // Attach session
    if (rte_crypto_op_attach_sym_session(op, session) < 0) {
        printf("Failed to attach session\n");
        rte_pktmbuf_free(mbuf);
        rte_crypto_op_free(op);
        rte_cryptodev_sym_session_free(crypto_dev_id, session);
        return -1;
    }
    
    // Setup cipher parameters
    sym_op->cipher.data.offset = 16; // Skip IV
    sym_op->cipher.data.length = plaintext_len;
    
    // Enqueue operation
    ret = rte_cryptodev_enqueue_burst(crypto_dev_id, 0, &op, 1);
    if (ret != 1) {
        printf("Failed to enqueue crypto operation\n");
        rte_pktmbuf_free(mbuf);
        rte_crypto_op_free(op);
        rte_cryptodev_sym_session_free(crypto_dev_id, session);
        return -1;
    }
    
    // Dequeue operation (blocking)
    int dequeued = 0;
    while (dequeued == 0) {
        dequeued = rte_cryptodev_dequeue_burst(crypto_dev_id, 0, &op, 1);
    }
    
    // Check operation status
    if (op->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
        printf("Crypto operation failed with status: %d\n", op->status);
        rte_pktmbuf_free(mbuf);
        rte_crypto_op_free(op);
        rte_cryptodev_sym_session_free(crypto_dev_id, session);
        return -1;
    }
    
    // Copy result (skip IV)
    memcpy(ciphertext, rte_pktmbuf_mtod(mbuf, uint8_t *) + 16, plaintext_len);
    
    // Cleanup
    rte_pktmbuf_free(mbuf);
    rte_crypto_op_free(op);
    rte_cryptodev_sym_session_free(crypto_dev_id, session);
    
    return plaintext_len;
}

/**
 * Perform AES-256-CTR decryption
 */
int crypto_dpdk_decrypt(const uint8_t *ciphertext, int ciphertext_len,
                        const uint8_t *key, const uint8_t *iv, uint8_t *plaintext) {
    struct rte_crypto_op *op;
    struct rte_crypto_sym_op *sym_op;
    struct rte_mbuf *mbuf;
    void *session;
    struct rte_crypto_sym_xform cipher_xform;
    int ret;
    
    if (!crypto_initialized || crypto_mbuf_pool == NULL) {
        printf("ERROR: Crypto not initialized or mbuf pool not set\n");
        return -1;
    }
    
    // Setup cipher transform
    memset(&cipher_xform, 0, sizeof(cipher_xform));
    cipher_xform.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
    cipher_xform.next = NULL;
    cipher_xform.cipher.algo = RTE_CRYPTO_CIPHER_AES_CTR;
    cipher_xform.cipher.op = RTE_CRYPTO_CIPHER_OP_DECRYPT;
    cipher_xform.cipher.key.data = (uint8_t *)key;
    cipher_xform.cipher.key.length = 32; // AES-256
    cipher_xform.cipher.iv.offset = IV_OFFSET;
    cipher_xform.cipher.iv.length = 16;
    
    // Create session
    session = rte_cryptodev_sym_session_create(crypto_dev_id, &cipher_xform, session_pool);
    if (session == NULL) {
        printf("Failed to create decryption session\n");
        return -1;
    }
    
    // Allocate crypto operation
    op = rte_crypto_op_alloc(crypto_op_pool, RTE_CRYPTO_OP_TYPE_SYMMETRIC);
    if (op == NULL) {
        printf("Failed to allocate crypto operation\n");
        rte_cryptodev_sym_session_free(crypto_dev_id, session);
        return -1;
    }
    
    // Allocate mbuf
    mbuf = rte_pktmbuf_alloc(crypto_mbuf_pool);
    if (mbuf == NULL) {
        printf("Failed to allocate mbuf\n");
        rte_crypto_op_free(op);
        rte_cryptodev_sym_session_free(crypto_dev_id, session);
        return -1;
    }
    
    // Append IV + data to mbuf
    uint8_t *data = (uint8_t *)rte_pktmbuf_append(mbuf, 16 + ciphertext_len);
    if (data == NULL) {
        printf("Failed to append data to mbuf\n");
        rte_pktmbuf_free(mbuf);
        rte_crypto_op_free(op);
        rte_cryptodev_sym_session_free(crypto_dev_id, session);
        return -1;
    }
    
    // Copy IV and ciphertext
    memcpy(data, iv, 16);
    memcpy(data + 16, ciphertext, ciphertext_len);
    
    // Setup symmetric operation
    sym_op = op->sym;
    sym_op->m_src = mbuf;
    sym_op->m_dst = NULL; // In-place operation
    
    // Attach session
    if (rte_crypto_op_attach_sym_session(op, session) < 0) {
        printf("Failed to attach session\n");
        rte_pktmbuf_free(mbuf);
        rte_crypto_op_free(op);
        rte_cryptodev_sym_session_free(crypto_dev_id, session);
        return -1;
    }
    
    // Setup cipher parameters
    sym_op->cipher.data.offset = 16; // Skip IV
    sym_op->cipher.data.length = ciphertext_len;
    
    // Enqueue operation
    ret = rte_cryptodev_enqueue_burst(crypto_dev_id, 0, &op, 1);
    if (ret != 1) {
        printf("Failed to enqueue crypto operation\n");
        rte_pktmbuf_free(mbuf);
        rte_crypto_op_free(op);
        rte_cryptodev_sym_session_free(crypto_dev_id, session);
        return -1;
    }
    
    // Dequeue operation (blocking)
    int dequeued = 0;
    while (dequeued == 0) {
        dequeued = rte_cryptodev_dequeue_burst(crypto_dev_id, 0, &op, 1);
    }
    
    // Check operation status
    if (op->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
        printf("Crypto operation failed with status: %d\n", op->status);
        rte_pktmbuf_free(mbuf);
        rte_crypto_op_free(op);
        rte_cryptodev_sym_session_free(crypto_dev_id, session);
        return -1;
    }
    
    // Copy result (skip IV)
    memcpy(plaintext, rte_pktmbuf_mtod(mbuf, uint8_t *) + 16, ciphertext_len);
    
    // Cleanup
    rte_pktmbuf_free(mbuf);
    rte_crypto_op_free(op);
    rte_cryptodev_sym_session_free(crypto_dev_id, session);
    
    return ciphertext_len;
}

/**
 * Calculate HMAC-SHA256
 */
int crypto_dpdk_hmac_sha256(const uint8_t *data, size_t data_len,
                            const uint8_t *key, size_t key_len, uint8_t *hmac_out) {
    struct rte_crypto_op *op;
    struct rte_crypto_sym_op *sym_op;
    struct rte_mbuf *mbuf;
    void *session;
    struct rte_crypto_sym_xform auth_xform;
    int ret;
    
    if (!crypto_initialized || crypto_mbuf_pool == NULL) {
        printf("ERROR: Crypto not initialized or mbuf pool not set\n");
        return -1;
    }
    
    // Setup auth transform
    memset(&auth_xform, 0, sizeof(auth_xform));
    auth_xform.type = RTE_CRYPTO_SYM_XFORM_AUTH;
    auth_xform.next = NULL;
    auth_xform.auth.algo = RTE_CRYPTO_AUTH_SHA256_HMAC;
    auth_xform.auth.op = RTE_CRYPTO_AUTH_OP_GENERATE;
    auth_xform.auth.digest_length = 32;
    auth_xform.auth.key.data = (uint8_t *)key;
    auth_xform.auth.key.length = key_len;
    
    // Create session
    session = rte_cryptodev_sym_session_create(crypto_dev_id, &auth_xform, session_pool);
    if (session == NULL) {
        printf("Failed to create HMAC session\n");
        return -1;
    }
    
    // Allocate crypto operation
    op = rte_crypto_op_alloc(crypto_op_pool, RTE_CRYPTO_OP_TYPE_SYMMETRIC);
    if (op == NULL) {
        printf("Failed to allocate crypto operation\n");
        rte_cryptodev_sym_session_free(crypto_dev_id, session);
        return -1;
    }
    
    // Allocate mbuf for data + digest
    mbuf = rte_pktmbuf_alloc(crypto_mbuf_pool);
    if (mbuf == NULL) {
        printf("Failed to allocate mbuf\n");
        rte_crypto_op_free(op);
        rte_cryptodev_sym_session_free(crypto_dev_id, session);
        return -1;
    }
    
    uint8_t *buf = (uint8_t *)rte_pktmbuf_append(mbuf, data_len + 32);
    if (buf == NULL) {
        printf("Failed to append data to mbuf\n");
        rte_pktmbuf_free(mbuf);
        rte_crypto_op_free(op);
        rte_cryptodev_sym_session_free(crypto_dev_id, session);
        return -1;
    }
    memcpy(buf, data, data_len);
    
    // Setup symmetric operation
    sym_op = op->sym;
    sym_op->m_src = mbuf;
    sym_op->m_dst = NULL;
    
    // Attach session
    if (rte_crypto_op_attach_sym_session(op, session) < 0) {
        printf("Failed to attach session\n");
        rte_pktmbuf_free(mbuf);
        rte_crypto_op_free(op);
        rte_cryptodev_sym_session_free(crypto_dev_id, session);
        return -1;
    }
    
    // Setup auth parameters
    sym_op->auth.data.offset = 0;
    sym_op->auth.data.length = data_len;
    sym_op->auth.digest.data = buf + data_len;
    sym_op->auth.digest.phys_addr = rte_pktmbuf_iova_offset(mbuf, data_len);
    
    // Enqueue operation
    ret = rte_cryptodev_enqueue_burst(crypto_dev_id, 0, &op, 1);
    if (ret != 1) {
        printf("Failed to enqueue crypto operation\n");
        rte_pktmbuf_free(mbuf);
        rte_crypto_op_free(op);
        rte_cryptodev_sym_session_free(crypto_dev_id, session);
        return -1;
    }
    
    // Dequeue operation (blocking)
    int dequeued = 0;
    while (dequeued == 0) {
        dequeued = rte_cryptodev_dequeue_burst(crypto_dev_id, 0, &op, 1);
    }
    
    // Check operation status
    if (op->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
        printf("Crypto operation failed with status: %d\n", op->status);
        rte_pktmbuf_free(mbuf);
        rte_crypto_op_free(op);
        rte_cryptodev_sym_session_free(crypto_dev_id, session);
        return -1;
    }
    
    // Copy digest
    memcpy(hmac_out, buf + data_len, 32);
    
    // Cleanup
    rte_pktmbuf_free(mbuf);
    rte_crypto_op_free(op);
    rte_cryptodev_sym_session_free(crypto_dev_id, session);
    
    return 0;
}

/**
 * Dummy implementation for sessions init (not needed with per-operation sessions)
 */
int crypto_sessions_init(const uint8_t *aes_key, size_t aes_key_len,
                         const uint8_t *hmac_key, size_t hmac_key_len) {
    // Not needed - we create sessions per operation
    (void)aes_key;
    (void)aes_key_len;
    (void)hmac_key;
    (void)hmac_key_len;
    printf("Using per-operation crypto sessions\n");
    return 0;
}

/**
 * Cleanup crypto resources
 */
void crypto_dpdk_cleanup(void) {
    if (!crypto_initialized) {
        return;
    }
    
    // Stop crypto device
    rte_cryptodev_stop(crypto_dev_id);
    
    // Free mempools
    if (crypto_op_pool != NULL) {
        rte_mempool_free(crypto_op_pool);
    }
    if (session_pool != NULL) {
        rte_mempool_free(session_pool);
    }
    if (session_priv_pool != NULL) {
        rte_mempool_free(session_priv_pool);
    }
    
    crypto_initialized = 0;
    printf("Crypto resources cleaned up\n");
}
