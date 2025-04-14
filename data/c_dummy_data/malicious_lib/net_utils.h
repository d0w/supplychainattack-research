/*
 * Network Utilities Header
 * Provides network functions for client/server applications
 */

#ifndef NET_UTILS_H
#define NET_UTILS_H

#include <stddef.h>

/*
 * Initialize the network utilities library
 * Must be called before using any other functions
 *
 * Returns:
 *   0 on success, -1 on failure
 */
int net_init(void);

/*
 * Clean up resources used by the network utilities library
 * Should be called when done using the library
 */
void net_cleanup(void);

/*
 * Create a socket for the specified address family
 *
 * Parameters:
 *   address_family - Address family (e.g., AF_INET)
 *   type - Socket type (e.g., SOCK_STREAM)
 *   protocol - Protocol (usually 0)
 *
 * Returns:
 *   Socket file descriptor on success, -1 on failure
 */
int net_socket(int address_family, int type, int protocol);

/*
 * Connect to a remote host
 *
 * Parameters:
 *   sockfd - Socket file descriptor
 *   hostname - Remote host name or IP address
 *   port - Remote port
 *
 * Returns:
 *   0 on success, negative value on failure
 */
int net_connect(int sockfd, const char *hostname, int port);

/*
 * Bind socket to an address and port
 *
 * Parameters:
 *   sockfd - Socket file descriptor
 *   port - Port to bind to
 *
 * Returns:
 *   0 on success, -1 on failure
 */
int net_bind(int sockfd, int port);

/*
 * Make socket listen for connections
 *
 * Parameters:
 *   sockfd - Socket file descriptor
 *   backlog - Maximum queue length for pending connections
 *
 * Returns:
 *   0 on success, -1 on failure
 */
int net_listen(int sockfd, int backlog);

/*
 * Accept a connection on a socket
 *
 * Parameters:
 *   sockfd - Socket file descriptor
 *   client_ip - Buffer to store client IP address (can be NULL)
 *   client_port - Pointer to store client port (can be NULL)
 *
 * Returns:
 *   New socket file descriptor for the client on success, -1 on failure
 */
int net_accept(int sockfd, char *client_ip, int *client_port);

/*
 * Send data over a socket
 *
 * Parameters:
 *   sockfd - Socket file descriptor
 *   data - Data to send
 *   length - Length of data
 *
 * Returns:
 *   Number of bytes sent on success, -1 on failure
 */
int net_send(int sockfd, const void *data, size_t length);

/*
 * Receive data from a socket
 *
 * Parameters:
 *   sockfd - Socket file descriptor
 *   buffer - Buffer to store received data
 *   length - Maximum length of buffer
 *
 * Returns:
 *   Number of bytes received on success, 0 on connection closed, -1 on failure
 */
int net_recv(int sockfd, void *buffer, size_t length);

/*
 * Close a socket
 *
 * Parameters:
 *   sockfd - Socket file descriptor
 */
void net_close(int sockfd);

/*
 * Download a file from a URL
 *
 * Parameters:
 *   url - URL of the file to download
 *   filename - Local filename to save the downloaded file
 *
 * Returns:
 *   0 on success, non-zero on failure
 */
int net_download_file(const char *url, const char *filename);

/*
 * Send a UDP packet to the specified destination
 *
 * Parameters:
 *   dest_ip - Destination IP address
 *   dest_port - Destination port
 *   data - Data to send
 *   length - Length of data
 *
 * Returns:
 *   Number of bytes sent on success, -1 on failure
 */
int net_send_udp(const char *dest_ip, int dest_port, const void *data, size_t length);

#endif /* NET_UTILS_H */