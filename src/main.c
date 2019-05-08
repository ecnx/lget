/* ------------------------------------------------------------------
 * Lget - Main Program File
 * ------------------------------------------------------------------ */

#include "lget.h"

/* Show program usage message */
static void show_usage ( void )
{
    printf ( "usage: lget url file\n" );
}

/* Extract hostname from http url */
static int http_hostname ( const char *url, char *hostname, size_t limit )
{
    size_t len;
    const char *end;

    if ( strstr ( url, "http://" ) != url )
    {
        errno = EPROTO;
        return -1;
    }

    url += 7;

    for ( end = url; *end != '\0'; end++ )
    {
        if ( *end == '/' )
        {
            break;
        }
    }

    if ( ( len = end - url ) >= limit )
    {
        errno = ENOBUFS;
        return -1;
    }

    memcpy ( hostname, url, len );
    hostname[len] = '\0';

    return 0;
}

/* Extract path from http url */
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

/* Extract content length from http response */
static int http_content_len ( const char *response, size_t * content_len )
{
    const char *begin;
    const char *body;
    const char *s_content_len = "Content-Length: ";

    if ( ( begin = strstr ( response, s_content_len ) ) == NULL
        || ( body = strstr ( response, "\r\n\r\n" ) ) == NULL )
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

/* Extract http status code */
static int http_status ( const char *response, unsigned int *status )
{
    while ( *response != '\x20' && *response != '\0' )
    {
        response++;
    }

    if ( *response == '\0' )
    {
        errno = ENODATA;
        return -1;
    }

    if ( sscanf ( response, "%u", status ) <= 0 )
    {
        errno = EINVAL;
        return -1;
    }

    return 0;
}

/* Fetch cpntent over http protocol */
static int http_get ( const char *url, const char *basename, int fd );

/* Perform http redirect */
static int http_redirect ( const char *buffer, const char *hostname, const char *basename, int fd )
{
    size_t len;
    const char *begin;
    const char *end;
    char location[4096];
    char url[4096];
    const char *s_location = "Location: ";

    if ( ( begin = strstr ( buffer, s_location ) ) == NULL )
    {
        errno = ENODATA;
        return -1;
    }

    begin += strlen ( s_location );

    if ( ( end = strstr ( begin, "\r\n" ) ) == NULL )
    {
        errno = ENODATA;
        return -1;
    }

    if ( ( len = end - begin ) >= sizeof ( location ) )
    {
        errno = ENOBUFS;
        return -1;
    }

    memcpy ( location, begin, len );
    location[len] = '\0';

    if ( location[0] == '/' )
    {
        if ( 7 + strlen ( hostname ) + strlen ( location ) >= sizeof ( url ) )
        {
            errno = ENOBUFS;
            return -1;
        }

        memcpy ( url, "http://", 7 );
        memcpy ( 7 + url, hostname, strlen ( hostname ) );
        memcpy ( 7 + url + strlen ( hostname ), location, strlen ( location ) );
        url[7 + strlen ( hostname ) + strlen ( location )] = '\0';

    } else
    {
        memcpy ( url, location, strlen ( location ) + 1 );
    }

    return http_get ( url, basename, fd );
}

/* Fetch cpntent over http protocol */
static int http_get ( const char *url, const char *basename, int fd )
{
    int sock;
    unsigned int address;
    unsigned int status;
    unsigned int port = 80;
    size_t len;
    size_t sum;
    size_t limit;
    char *port_ptr;
    const char *path;
    const char *body = NULL;
    struct sockaddr_in saddr;
    char hostname[128];
    char buffer[32768];

    /* extract hostname from url http */
    if ( http_hostname ( url, hostname, sizeof ( hostname ) ) < 0 )
    {
        perror ( "parse" );
        return -1;
    }

    /* extract path from http url */
    if ( ( path = http_path ( url ) ) == NULL )
    {
        perror ( "parse" );
        return -1;
    }

    /* extract port number from hostname */
    if ( ( port_ptr = strchr ( hostname, ':' ) ) != NULL )
    {
        if ( sscanf ( port_ptr + 1, "%u", &port ) <= 0 )
        {
            errno = EINVAL;
            perror ( "parse" );
            return -1;
        }
        *port_ptr = '\0';
    }

    /* resolve server address */
    if ( nsaddr ( hostname, &address ) < 0 )
    {
        perror ( "nsaddr" );
        return -1;
    }

    /* restore hostname string */
    if ( port_ptr != NULL )
    {
        *port_ptr = ':';
    }

    /* prepare server address */
    memset ( &saddr, '\0', sizeof ( saddr ) );
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = address;
    saddr.sin_port = htons ( port );

    /* create server socket */
    if ( ( sock = socket ( AF_INET, SOCK_STREAM, 0 ) ) < 0 )
    {
        perror ( "socket" );
        return -1;
    }

    /* connect with server */
    if ( connect ( sock, ( struct sockaddr * ) &saddr, sizeof ( struct sockaddr_in ) ) < 0 )
    {
        perror ( "connect" );
        close ( sock );
        return -1;
    }

    /* prepare http request */
    snprintf ( buffer, sizeof ( buffer ),
        "GET %s HTTP/1.0\r\n"
        "Host: %s\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:61.0) Gecko/20100101 Firefox/61.0\r\n"
        "Accept-Language: en-US,en;q=0.5\r\n"
        "Accept-Encoding: \r\n" "Connection: close\r\n" "\r\n", path, hostname );

    /* send http request */
    for ( limit = strlen ( buffer ), sum = 0; sum < limit; sum += len )
    {
        if ( ( ssize_t ) ( len = send ( sock, buffer + sum, limit - sum, MSG_NOSIGNAL ) ) < 0 )
        {
            perror ( "send" );
            close ( sock );
            return -1;
        }
    }

    /* receive http response */
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
            return http_redirect ( buffer, hostname, basename, fd );
        }

        if ( status != 200 )
        {
            errno = status;
            perror ( "http status" );
            errno = EINVAL;
            close ( sock );
            return -1;
        }

        if ( ( body = strstr ( buffer, "\r\n\r\n" ) ) != NULL )
        {
            break;
        }
    }

    /* check if response header is complete */
    if ( body == NULL )
    {
        errno = E2BIG;
        perror ( "recv" );
        close ( sock );
        return -1;
    }

    body += 4;

    /* extract content length parameter */
    if ( http_content_len ( buffer, &limit ) < 0 )
    {
        perror ( "clen" );
        close ( sock );
        return -1;
    }

    /* copy first data slice */
    sum = buffer + sum - body;

    if ( sum )
    {
        if ( write ( fd, body, sum ) < 0 )
        {
            perror ( "write" );
            close ( sock );
            return -1;
        }

        printf ( "\r%s: %lu/%lu", basename, ( unsigned long ) sum, ( unsigned long ) limit );
    }

    /* further data receive */
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
            return -1;

        }

        if ( write ( fd, buffer, len ) < 0 )
        {
            perror ( "write" );
            close ( sock );
            return -1;
        }

        printf ( "\r%s: %lu/%lu", basename, ( unsigned long ) ( sum + len ),
            ( unsigned long ) limit );
    }

    printf ( " - OK\n" );
    close ( sock );

    return 0;
}

/* Main program function */
int main ( int argc, char *argv[] )
{
    int fd;
    const char *basename;

    /* validate arguments count */
    if ( argc < 3 )
    {
        show_usage (  );
        return 1;
    }

    /* open output file */
    if ( ( fd = open ( argv[2], O_CREAT | O_WRONLY | O_TRUNC, 0644 ) ) < 0 )
    {
        perror ( "open" );
        printf ( "error status: %i\n", errno );
        return 1;
    }

    /* obtain file basename */
    basename = argv[2];

    while ( strchr ( basename, '/' ) != NULL )
    {
        basename = strchr ( basename, '/' ) + 1;
    }

    /* download file over http protocol */
    if ( http_get ( argv[1], basename, fd ) < 0 )
    {
        printf ( "error status: %i\n", errno );
        close ( fd );
        return 1;
    }

    close ( fd );
    return 0;
}
