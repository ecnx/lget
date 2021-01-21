/* ------------------------------------------------------------------
 * Lget - Http Support
 * ------------------------------------------------------------------ */

#include "lget.h"

/**
 * Extract hostname from http url
 */
static int parse_http_host ( const char *url, char *hostname, size_t limit, unsigned short *port )
{
    size_t len;
    unsigned int lport = 80;
    const char *end;

    if ( strstr ( url, "http://" ) != url )
    {
        errno = EPROTO;
        return -1;
    }

    url += 7;
    end = url;

    while ( *end && *end != ':' && *end != '/' )
    {
        end++;
    }

    if ( ( len = end - url ) >= limit )
    {
        errno = ENOBUFS;
        return -1;
    }

    memcpy ( hostname, url, len );
    hostname[len] = '\0';

    if ( *end == ':' )
    {
        if ( sscanf ( end + 1, "%u", &lport ) <= 0 || lport > 65535 )
        {
            errno = EINVAL;
            return -1;
        }
    }
    *port = lport;

    return 0;
}

/**
 * Extract path from http url
 */
static const char *http_path ( const char *url )
{
    if ( strstr ( url, "http://" ) != url )
    {
        errno = EPROTO;
        return NULL;
    }

    url = strchr ( url + 7, '/' );

    return url ? url : "/";
}

/**
 * Extract content length from http response
 */
static int http_content_len ( const char *response, const char *body, size_t *content_len )
{
    const char *begin;
    const char *s_content_len = "content-length: ";

    if ( !( begin = lget_strcasestr ( response, s_content_len ) ) )
    {
        errno = ENODATA;
        return -1;
    }

    begin += strlen ( s_content_len );

    if ( begin > body )
    {
        errno = ENODATA;
        return -1;
    }

    if ( sscanf ( begin, "%lu", ( unsigned long * ) content_len ) <= 0 )
    {
        errno = EINVAL;
        return -1;
    }

    return 0;
}

/**
 * Extract http status code
 */
static int http_status ( const char *response, unsigned int *status )
{
    while ( *response && *response != '\x20' )
    {
        response++;
    }

    if ( !*response || sscanf ( response, "%u", status ) <= 0 )
    {
        errno = EINVAL;
        return -1;
    }

    return 0;
}

/**
 * Perform http redirect
 */
static int http_redirect ( const char *buffer, const char *hostname, const char *filepath,
    struct socks5_t *socks5 )
{
    size_t len;
    const char *begin;
    const char *end;
    char url[4096];
    const char *s_location = "location: ";

    if ( !( begin = lget_strcasestr ( buffer, s_location ) ) )
    {
        errno = ENODATA;
        return -1;
    }

    begin += strlen ( s_location );

    if ( !( end = strstr ( begin, "\r\n" ) ) )
    {
        errno = ENODATA;
        return -1;
    }

    if ( ( len = end - begin ) >= sizeof ( url ) )
    {
        errno = ENOBUFS;
        return -1;
    }

    if ( 7 + strlen ( hostname ) + len >= sizeof ( url ) )
    {
        errno = ENOBUFS;
        return -1;
    }

    if ( *begin == '/' )
    {
        memcpy ( url, "http://", 7 );
        memcpy ( url + 7, hostname, strlen ( hostname ) );
        memcpy ( url + 7 + strlen ( hostname ), begin, len );
        url[strlen ( hostname ) + len + 7] = '\0';

    } else
    {
        memcpy ( url, begin, len );
        url[len] = '\0';
    }

    printf ( "redirect: %s\n", url );
    return http_get ( url, filepath, socks5 );
}


/**
 * Download file via Http
 */
int http_get ( const char *url, const char *filepath, struct socks5_t *socks5 )
{
    int fd;
    int sock;
    unsigned int addr;
    unsigned int status;
    unsigned short port;
    size_t len;
    size_t sum;
    size_t limit;
    const char *path;
    const char *body = NULL;
    const char *basename;
    struct timeval tv;
    struct sockaddr_in saddr;
    char hostname[HOSTNAME_SIZE];
    char buffer[32768];

    /* Setup file basename */
    basename = get_basename ( filepath );

    /* Extract hostname from url http */
    if ( parse_http_host ( url, hostname, sizeof ( hostname ), &port ) < 0 )
    {
        perror ( "parse" );
        return -1;
    }

    /* Extract path from http url */
    if ( !( path = http_path ( url ) ) )
    {
        perror ( "parse" );
        return -1;
    }

    /* Prepare server address */
    memset ( &saddr, '\0', sizeof ( saddr ) );
    saddr.sin_family = AF_INET;

    /* Connect endpoint or proxy server */
    if ( socks5 )
    {
        saddr.sin_addr.s_addr = socks5->addr;
        saddr.sin_port = htons ( socks5->port );

    } else
    {
        /* Resolve server address */
        if ( resolve_ipv4 ( hostname, &addr ) < 0 )
        {
            perror ( "resolve" );
            return -1;
        }
        saddr.sin_addr.s_addr = addr;
        saddr.sin_port = htons ( port );
    }

    /* Create server socket */
    if ( ( sock = socket ( AF_INET, SOCK_STREAM, 0 ) ) < 0 )
    {
        perror ( "socket" );
        return -1;
    }

    tv.tv_sec = 4;
    tv.tv_usec = 0;
    setsockopt ( sock, SOL_SOCKET, SO_SNDTIMEO, ( const char * ) &tv, sizeof ( tv ) );

    /* Set socket receive timeuot */
    tv.tv_sec = 4;
    tv.tv_usec = 0;
    setsockopt ( sock, SOL_SOCKET, SO_RCVTIMEO, ( const char * ) &tv, sizeof ( tv ) );

    /* Connect with server */
    if ( connect ( sock, ( struct sockaddr * ) &saddr, sizeof ( struct sockaddr_in ) ) < 0 )
    {
        perror ( "connect" );
        close ( sock );
        return -1;
    }

    /* Setup Socks5 connection if needed */
    if ( socks5 )
    {
        /* Perform Socks5 handshake */
        if ( socks5_handshake ( sock ) < 0 )
        {
            perror ( "socks5 handshake" );
            return -1;
        }

        /* Perform Socks5 request */
        if ( socks5_request_hostname ( sock, hostname, port ) < 0 )
        {
            perror ( "socks5 request" );
            return -1;
        }
    }

    /* Prepare http request */
    snprintf ( buffer, sizeof ( buffer ),
        "GET %s HTTP/1.0\r\n"
        "Host: %s\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:61.0) Gecko/20100101 Firefox/61.0\r\n"
        "Accept-Language: en-US,en;q=0.5\r\n"
        "Accept-Encoding: \r\n" "Connection: close\r\n" "\r\n", path, hostname );

    /* Send http request */
    for ( limit = strlen ( buffer ), sum = 0; sum < limit; sum += len )
    {
        if ( ( ssize_t ) ( len = send ( sock, buffer + sum, limit - sum, MSG_NOSIGNAL ) ) < 0 )
        {
            perror ( "send" );
            close ( sock );
            return -1;
        }
    }

    /* Receive http response */
    for ( sum = 0; sum < sizeof ( buffer ); )
    {
        if ( ( ssize_t ) ( len =
                recv ( sock, buffer + sum, sizeof ( buffer ) - sum - 1, 0 ) ) <= 0 )
        {
            if ( !errno )
            {
                errno = EPIPE;
            }
            perror ( "recv" );
            close ( sock );
            return -1;
        }

        sum += len;
        buffer[sum] = '\0';

        if ( http_status ( buffer, &status ) < 0 )
        {
            continue;
        }

        if ( status == 300 || status == 301 || status == 302 )
        {
            close ( sock );
            return http_redirect ( buffer, hostname, filepath, socks5 );
        }

        if ( status != 200 )
        {
            errno = status;
            perror ( "http status" );
            errno = EINVAL;
            close ( sock );
            return -1;
        }

        if ( ( body = strstr ( buffer, "\r\n\r\n" ) ) )
        {
            break;
        }
    }

    /* Check if response header is complete */
    if ( !body )
    {
        errno = E2BIG;
        perror ( "recv" );
        close ( sock );
        return -1;
    }

    body += 4;

    /* Extract content length parameter */
    if ( http_content_len ( buffer, body, &limit ) < 0 )
    {
        perror ( "clen" );
        close ( sock );
        return -1;
    }

    /* Open output file */
    if ( ( fd = open ( filepath, O_CREAT | O_WRONLY | O_TRUNC, 0644 ) ) < 0 )
    {
        perror ( "open" );
        return -1;
    }

    /* Copy first data slice */
    sum = buffer + sum - body;

    if ( sum )
    {
        if ( write ( fd, body, sum ) < 0 )
        {
            perror ( "write" );
            close ( sock );
            close ( fd );
            return -1;
        }

        printf ( "\r%s: %lu/%lu", basename, ( unsigned long ) sum, ( unsigned long ) limit );
    }

    /* Further data receive */
    for ( ; sum < limit; sum += len )
    {
        len = limit - sum;

        if ( len > sizeof ( buffer ) )
        {
            len = sizeof ( buffer );
        }

        if ( ( ssize_t ) ( len = recv ( sock, buffer, len, 0 ) ) <= 0 )
        {
            if ( !errno )
            {
                errno = EPIPE;
            }
            perror ( "recv" );
            close ( sock );
            close ( fd );
            return -1;

        }

        if ( write ( fd, buffer, len ) < 0 )
        {
            perror ( "write" );
            close ( sock );
            close ( fd );
            return -1;
        }

        printf ( "\r%s: %lu/%lu", basename, ( unsigned long ) ( sum + len ),
            ( unsigned long ) limit );
    }

    printf ( " - OK\n" );
    close ( sock );
    close ( fd );

    return 0;
}
