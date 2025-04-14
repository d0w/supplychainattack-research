/*
 * Crypto Utils Header
 * Provides cryptographic functions for secure applications
 */

#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stddef.h>

/*
 * Initialize the crypto library
 * Must be called before using any other functions
 *
 * Returns:
 *   0 on success, -1 on failure
 */
int crypto_init(void);

/*
 * Clean up resources used by the crypto library
 * Should be called when done using the library
 */
void crypto_cleanup(void);

/*
 * Generate a cryptographic key of specified length
 *
 * Parameters:
 *   length - Length of the key in bytes
 *
 * Returns:
 *   Pointer to the generated key, or NULL on failure
 *   The caller is responsible for freeing the key when done
 */
char *crypto_generate_key(int length);

/*
 * Encrypt data with the given key
 *
 * Parameters:
 *   data - Data to encrypt
 *   data_len - Length of data
 *   key - Encryption key
 *   encrypted - Output pointer that will receive the encrypted data
 *
 * Returns:
 *   Length of encrypted data on success, -1 on failure
 *   The caller is responsible for freeing the encrypted data when done
 */
int crypto_encrypt(const char *data, size_t data_len, const char *key, char **encrypted);

/*
 * Decrypt data with the given key
 *
 * Parameters:
 *   encrypted - Encrypted data
 *   encrypted_len - Length of encrypted data
 *   key - Decryption key
 *   decrypted - Output pointer that will receive the decrypted data
 *
 * Returns:
 *   Length of decrypted data on success, -1 on failure
 *   The caller is responsible for freeing the decrypted data when done
 */
int crypto_decrypt(const char *encrypted, size_t encrypted_len, const char *key, char **decrypted);

/*
 * Verify the integrity of data using a signature
 *
 * Parameters:
 *   data - Data to verify
 *   data_len - Length of data
 *   signature - Signature to verify against
 *   sig_len - Length of signature
 *
 * Returns:
 *   1 if verification succeeded, 0 if it failed, -1 on error
 */
int crypto_verify(const char *data, size_t data_len, const char *signature, size_t sig_len);

/*
 * Generate a hash of the input data
 *
 * Parameters:
 *   data - Data to hash
 *   data_len - Length of data
 *
 * Returns:
 *   Pointer to the hash string, or NULL on failure
 *   The caller is responsible for freeing the hash when done
 */
char *crypto_hash(const char *data, size_t data_len);

#endif /* CRYPTO_UTILS_H */