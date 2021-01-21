/* ------------------------------------------------------------------
 * Lget - Socks5 Proxy Support
 * ------------------------------------------------------------------ */

#include "lget.h"

/*
 * Perform Socks5 handshake
 */
int socks5_handshake ( int sock )
{
    ssize_t len;
    char buffer[32];

    /* Version 5, one method: no authentication */
    buffer[0] = 5;      /* socks version */
    buffer[1] = 1;      /* one method */
    buffer[2] = 0;      /* no auth */

    /* Estabilish session with proxy server */
    if ( send ( sock, buffer, 3, MSG_NOSIGNAL ) <= 0 )
    {
        return -1;
    }

    /* Receive operation status */
    if ( ( len = recv ( sock, buffer, sizeof ( buffer ) - 1, 0 ) ) <= 0 )
    {
        return -1;
    }

    /* Detect broken pipe */
    if ( !len )
    {
        errno = EPIPE;
        return -1;
    }

    /* Analyse received response */
    if ( len != 2 || buffer[0] != 5 || buffer[1] != 0 )
    {
        errno = EINVAL;
        return -1;
    }

    /* Handshake success */
    return 0;
}

/**
 * Request new Socks5 connection
 */
int socks5_request_hostname ( int sock, const char *hostname, unsigned short port )
{
    ssize_t len;
    size_t hostlen;
    char buffer[HOSTNAME_SIZE + 32];

    /* Put port number into network byte order */
    port = htons ( port );

    /* Get hostname string length */
    if ( ( hostlen = strlen ( hostname ) ) > HOSTNAME_SIZE )
    {
        errno = ENOBUFS;
        return -1;
    }

    /* Version 5, one method: no authentication */
    buffer[0] = 5;      /* socks version */
    buffer[1] = 1;      /* connect */
    buffer[2] = 0;      /* reserved */
    buffer[3] = 3;      /* hostname */

    buffer[4] = hostlen;        /* hostname length */
    memcpy ( buffer + 5, hostname, hostlen );   /* hostname */
    buffer[5 + hostlen] = port >> 8;    /* port number 1'st byte */
    buffer[6 + hostlen] = port & 0xff;  /* port number 2'nd byte */

    /* Send request to SOCK5 proxy server */
    if ( send ( sock, buffer, hostlen + 7, MSG_NOSIGNAL ) <= 0 )
    {
        return -1;
    }

    /* Receive operation status */
    if ( ( len = recv ( sock, buffer, sizeof ( buffer ) - 1, 0 ) ) < 0 )
    {
        return -1;
    }

    /* Detect broken pipe */
    if ( !len )
    {
        errno = EPIPE;
        return -1;
    }

    /* Analyse received response */
    if ( len < 4 || buffer[0] != 5 || buffer[1] != 0 || buffer[3] != 1 )
    {
        errno = EINVAL;
        return -1;
    }

    /* Request success */
    return 0;
}
