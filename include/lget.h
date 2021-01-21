/* ------------------------------------------------------------------
 * Lget - Project Shared Header
 * ------------------------------------------------------------------ */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "dns.h"

#ifndef LGET_H
#define LGET_H

#define HOSTNAME_SIZE 256

/**
 * Socks5 proxy details with hostname unresolved
 */
struct socks5h_t
{
    char hostname[HOSTNAME_SIZE];
    unsigned short port;
};

/**
 * Socks5 proxy details with hostname resolved
 */
struct socks5_t
{
    unsigned int addr;
    unsigned short port;
};

/**
 * Download file via Http
 */
extern int http_get ( const char *url, const char *filepath, struct socks5_t *socks5 );

/*
 * Perform Socks5 handshake
 */
extern int socks5_handshake ( int sock );

/**
 * Request new Socks5 connection
 */
extern int socks5_request_hostname ( int sock, const char *hostname, unsigned short port );

/**
 * Parse host name and port
 */
extern int parse_host ( const char *input, char *host, size_t host_len, unsigned short *port );

/**
 * Get basename of file path
 */
extern const char *get_basename ( const char *path );

/**
 * Find substring with case ignored
 */
extern char *lget_strcasestr ( const char *haystack, const char *needle );

/**
 * Resolve hostname into IPv4 address
 */
extern int resolve_ipv4 ( const char *hostname, unsigned int *addr );

#endif
