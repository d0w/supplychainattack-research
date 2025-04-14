/*
 * Secure Messenger Application
 * A simple encrypted chat application using our libraries
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include "../malicious_lib/crypto_utils.h"
#include "../malicious_lib/net_utils.h"
#include <sys/socket.h>
#include <netinet/in.h>

#define DEFAULT_PORT 7890
#define MAX_BUFFER 4096
#define MAX_USERNAME 32

// Global variables
int server_socket = -1;
int client_socket = -1;
int running = 1;
char username[MAX_USERNAME];
char *encryption_key = NULL;

// Forward declarations
void cleanup(void);
void handle_signal(int sig);
void *receive_thread(void *arg);
int start_server(int port);
int connect_to_server(const char *hostname, int port);
void chat_loop(void);

int main(int argc, char *argv[]) {
    // Set up signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    // Register cleanup function
    atexit(cleanup);
    
    // Initialize libraries
    if (crypto_init() != 0) {
        fprintf(stderr, "Failed to initialize crypto library\n");
        return 1;
    }
    
    if (net_init() != 0) {
        fprintf(stderr, "Failed to initialize network library\n");
        return 1;
    }
    
    // Generate encryption key
    encryption_key = crypto_generate_key(32);
    if (!encryption_key) {
        fprintf(stderr, "Failed to generate encryption key\n");
        return 1;
    }
    
    printf("Secure Messenger\n");
    printf("----------------\n");
    
    // Get username
    printf("Enter your username: ");
    fgets(username, MAX_USERNAME, stdin);
    username[strcspn(username, "\n")] = 0;  // Remove newline
    
    // Check command line arguments
    if (argc < 2) {
        printf("Usage:\n");
        printf("  %s -s [port]         # Start as server\n", argv[0]);
        printf("  %s -c hostname [port] # Connect to server\n", argv[0]);
        return 1;
    }
    
    int port = DEFAULT_PORT;
    
    // Parse port if provided
    if ((strcmp(argv[1], "-s") == 0 && argc > 2) || 
        (strcmp(argv[1], "-c") == 0 && argc > 3)) {
        
        int arg_index = (strcmp(argv[1], "-s") == 0) ? 2 : 3;
        port = atoi(argv[arg_index]);
        
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "Invalid port number\n");
            return 1;
        }
    }
    
    // Start server or client mode
    if (strcmp(argv[1], "-s") == 0) {
        printf("Starting server on port %d...\n", port);
        if (start_server(port) != 0) {
            return 1;
        }
    } else if (strcmp(argv[1], "-c") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Missing hostname\n");
            return 1;
        }
        
        printf("Connecting to %s:%d...\n", argv[2], port);
        if (connect_to_server(argv[2], port) != 0) {
            return 1;
        }
    } else {
        fprintf(stderr, "Invalid option: %s\n", argv[1]);
        return 1;
    }
    
    // Start chat
    chat_loop();
    
    return 0;
}

// Clean up resources
void cleanup(void) {
    running = 0;
    
    // Close sockets
    if (client_socket >= 0) {
        net_close(client_socket);
        client_socket = -1;
    }
    
    if (server_socket >= 0) {
        net_close(server_socket);
        server_socket = -1;
    }
    
    // Free encryption key
    if (encryption_key) {
        free(encryption_key);
        encryption_key = NULL;
    }
    
    // Clean up libraries
    crypto_cleanup();
    net_cleanup();
    
    printf("\nSecure Messenger terminated\n");
}

// Handle signals
void handle_signal(int sig) {
    printf("\nReceived signal %d, terminating...\n", sig);
    exit(0);
}

// Thread for receiving messages
void *receive_thread(void *arg) {
    int socket_fd = *((int *)arg);
    char buffer[MAX_BUFFER];
    char *decrypted = NULL;
    
    while (running) {
        // Receive encrypted message
        memset(buffer, 0, sizeof(buffer));
        int bytes = net_recv(socket_fd, buffer, sizeof(buffer) - 1);
        
        if (bytes <= 0) {
            // Connection closed or error
            printf("\nConnection closed by remote host\n");
            running = 0;
            break;
        }
        
        // Decrypt message
        if (crypto_decrypt(buffer, bytes, encryption_key, &decrypted) < 0) {
            fprintf(stderr, "Failed to decrypt message\n");
            continue;
        }
        
        // Display message
        printf("\n%s\n", decrypted);
        printf("You: ");
        fflush(stdout);
        
        // Free decrypted message
        free(decrypted);
    }
    
    return NULL;
}

// Start server
int start_server(int port) {
    char client_ip[16];
    int client_port;
    
    // Create socket
    server_socket = net_socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Failed to create socket");
        return -1;
    }
    
    // Bind socket
    if (net_bind(server_socket, port) < 0) {
        perror("Failed to bind socket");
        return -1;
    }
    
    // Listen for connections
    if (net_listen(server_socket, 5) < 0) {
        perror("Failed to listen on socket");
        return -1;
    }
    
    printf("Waiting for connection...\n");
    
    // Accept client connection
    client_socket = net_accept(server_socket, client_ip, &client_port);
    if (client_socket < 0) {
        perror("Failed to accept connection");
        return -1;
    }
    
    printf("Client connected from %s:%d\n", client_ip, client_port);
    
    // Send encryption key
    char message[MAX_BUFFER];
    snprintf(message, sizeof(message), "KEY:%s", encryption_key);
    net_send(client_socket, message, strlen(message));
    
    // Start receive thread
    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, receive_thread, &client_socket) != 0) {
        perror("Failed to create receive thread");
        return -1;
    }
    
    pthread_detach(thread_id);
    
    return 0;
}

// Connect to server
int connect_to_server(const char *hostname, int port) {
    // Create socket
    client_socket = net_socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0) {
        perror("Failed to create socket");
        return -1;
    }
    
    // Connect to server
    if (net_connect(client_socket, hostname, port) < 0) {
        perror("Failed to connect to server");
        return -1;
    }
    
    printf("Connected to server\n");
    
    // Receive encryption key
    char buffer[MAX_BUFFER];
    memset(buffer, 0, sizeof(buffer));
    int bytes = net_recv(client_socket, buffer, sizeof(buffer) - 1);
    
    if (bytes <= 0) {
        perror("Failed to receive encryption key");
        return -1;
    }
    
    // Parse key
    if (strncmp(buffer, "KEY:", 4) == 0) {
        // Replace our key with the one from server
        if (encryption_key) {
            free(encryption_key);
        }
        encryption_key = strdup(buffer + 4);
        
        if (!encryption_key) {
            perror("Failed to allocate memory for key");
            return -1;
        }
    } else {
        fprintf(stderr, "Invalid key format received\n");
        return -1;
    }
    
    // Start receive thread
    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, receive_thread, &client_socket) != 0) {
        perror("Failed to create receive thread");
        return -1;
    }
    
    pthread_detach(thread_id);
    
    return 0;
}

// Main chat loop
void chat_loop(void) {
    char input[MAX_BUFFER];
    char formatted[MAX_BUFFER + MAX_USERNAME];
    char *encrypted = NULL;
    
    printf("Type your messages (Ctrl+C to quit):\n");
    
    while (running) {
        printf("You: ");
        
        // Get user input
        if (fgets(input, sizeof(input), stdin) == NULL) {
            break;
        }
        
        // Remove newline
        input[strcspn(input, "\n")] = 0;
        
        // Check for exit command
        if (strcmp(input, "/quit") == 0 || strcmp(input, "/exit") == 0) {
            break;
        }
        
        // Format message with username
        snprintf(formatted, sizeof(formatted), "%s: %s", username, input);
        
        // Encrypt message
        int encrypted_len = crypto_encrypt(formatted, strlen(formatted), 
                                          encryption_key, &encrypted);
        
        if (encrypted_len < 0) {
            fprintf(stderr, "Failed to encrypt message\n");
            continue;
        }
        
        // Send encrypted message
        if (net_send(client_socket, encrypted, encrypted_len) < 0) {
            fprintf(stderr, "Failed to send message\n");
        }
        
        // Free encrypted message
        free(encrypted);
    }
    
    // Exit program
    exit(0);
}