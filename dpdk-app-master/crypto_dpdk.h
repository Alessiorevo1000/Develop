#ifndef CRYPTO_DPDK_H
#define CRYPTO_DPDK_H

#include <stdint.h>
#include <stddef.h>
#include <rte_mbuf.h>

/**
 * Initialize DPDK cryptodev device and memory pools
 * Must be called after rte_eal_init()
 * 
 * @return: 0 on success, -1 on failure
 */
int crypto_dpdk_init(void);

/**
 * Initialize crypto sessions with pre-shared keys
 * 
 * @param aes_key: AES-256 key (32 bytes)
 * @param aes_key_len: Length of AES key
 * @param hmac_key: HMAC-SHA256 key
 * @param hmac_key_len: Length of HMAC key
 * @return: 0 on success, -1 on failure
 */
int crypto_sessions_init(const uint8_t *aes_key, size_t aes_key_len,
                         const uint8_t *hmac_key, size_t hmac_key_len);

/**
 * Perform AES-256-CTR encryption using hardware acceleration
 * 
 * @param plaintext: Input data to encrypt
 * @param plaintext_len: Length of plaintext
 * @param key: Encryption key (32 bytes for AES-256)
 * @param iv: Initialization vector (nonce) - 16 bytes
 * @param ciphertext: Output buffer for encrypted data
 * @return: Length of ciphertext on success, -1 on failure
 */
int crypto_dpdk_encrypt(const uint8_t *plaintext, int plaintext_len,
                        const uint8_t *key, const uint8_t *iv, uint8_t *ciphertext);

/**
 * Perform AES-256-CTR decryption using hardware acceleration
 * 
 * @param ciphertext: Input data to decrypt
 * @param ciphertext_len: Length of ciphertext
 * @param key: Decryption key (32 bytes for AES-256)
 * @param iv: Initialization vector (nonce) - 16 bytes
 * @param plaintext: Output buffer for decrypted data
 * @return: Length of plaintext on success, -1 on failure
 */
int crypto_dpdk_decrypt(const uint8_t *ciphertext, int ciphertext_len,
                        const uint8_t *key, const uint8_t *iv, uint8_t *plaintext);

/**
 * Calculate HMAC-SHA256 using hardware acceleration
 * 
 * @param data: Input data
 * @param data_len: Length of input data
 * @param key: HMAC key
 * @param key_len: Length of HMAC key
 * @param hmac_out: Output buffer for HMAC (32 bytes)
 * @return: 0 on success, -1 on failure
 */
int crypto_dpdk_hmac_sha256(const uint8_t *data, size_t data_len,
                            const uint8_t *key, size_t key_len, uint8_t *hmac_out);

/**
 * Set the mbuf pool for crypto operations
 * Must be called before using crypto functions
 */
void crypto_dpdk_set_mbuf_pool(struct rte_mempool *pool);

/**
 * Cleanup crypto resources
 * Should be called before application exit
 */
void crypto_dpdk_cleanup(void);

#endif // CRYPTO_DPDK_H
