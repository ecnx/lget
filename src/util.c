/* ------------------------------------------------------------------
 * Lget - Utility Functions
 * ------------------------------------------------------------------ */

#include "lget.h"

/**
 * Parse host name and port
 */
int parse_host ( const char *input, char *host, size_t host_len, unsigned short *port )
{
    unsigned int lport;
    size_t len;
    const char *ptr;

    if ( !( ptr = strchr ( input, ':' ) ) )
    {
        return -1;
    }

    if ( ( len = ptr - input ) >= host_len )
    {
        return -1;
    }

    memcpy ( host, input, len );
    host[len] = '\0';

    ptr++;

    if ( sscanf ( ptr, "%u", &lport ) <= 0 || lport > 65535 )
    {
        return -1;
    }

    *port = lport;
    return 0;
}

/**
 * Get basename of file path
 */
const char *get_basename ( const char *path )
{
    while ( strchr ( path, '/' ) )
    {
        path = strchr ( path, '/' ) + 1;
    }
    return path;
}

/**
 * Find substring with case ignored
 */
char *lget_strcasestr ( const char *haystack, const char *needle )
{
    size_t i;
    size_t j;
    size_t haystack_len;
    size_t needle_len;

    haystack_len = strlen ( haystack );
    needle_len = strlen ( needle );

    if ( needle_len > haystack_len )
    {
        return NULL;
    }

    haystack_len -= needle_len;

    for ( i = 0; i <= haystack_len; i++ )
    {
        for ( j = 0; j < needle_len; j++ )
        {
            if ( tolower ( haystack[i + j] ) != tolower ( needle[j] ) )
            {
                break;
            }
        }

        if ( j == needle_len )
        {
            return ( char * ) ( haystack + i );
        }
    }

    return NULL;
}

/**
 * Resolve hostname into IPv4 address
 */
int resolve_ipv4 ( const char *hostname, unsigned int *addr )
{
#ifdef SYSTEM_RESOLVER
    struct hostent *he;
    struct in_addr **addr_list;

#ifndef DISABLE_INET_PTON
    if ( inet_pton ( AF_INET, hostname, addr ) > 0 )
    {
        return 0;
    }
#endif

    /* Query host addess */
    if ( !( he = gethostbyname ( hostname ) ) )
    {
        return -1;
    }

    /* Assign list pointer */
    addr_list = ( struct in_addr ** ) he->h_addr_list;

    /* At least one address required */
    if ( !addr_list[0] )
    {
        errno = ENODATA;
        return -1;
    }

    /* Assign host address */
    *addr = ( *addr_list )[0].s_addr;

    return 0;
#else

#ifndef DISABLE_INET_PTON
    if ( inet_pton ( AF_INET, hostname, addr ) > 0 )
    {
        return 0;
    }
#endif

    return nsaddr ( hostname, addr );
#endif
}
