/* ------------------------------------------------------------------
 * LibDNS - Portable DNS Client
 * ------------------------------------------------------------------ */

#include "dns.h"
#include "dns-root.h"

/**
 * Count of DNS Root Servers
 */
#define DNS_N_SERVERS (sizeof(dns_servers) / sizeof(unsigned int))

/**
 * Encode hostname like www.example.com into 3www7example3com
 */
static int dns_encode_hostname ( const char *in, unsigned char *out, size_t osize )
{
    size_t len = 0;
    char *ptr;
    unsigned char *limit;

    limit = out + osize;

    while ( out < limit )
    {
        if ( !*in )
        {
            *out = 0;
            return 0;
        }

        ptr = strchr ( in, '.' );
        len = ptr ? ( size_t ) ( ptr - in ) : strlen ( in );

        if ( !len || len > 255 || out + len + 1 > limit )
        {
            break;
        }

        *out = len;
        memcpy ( out + 1, in, len );

        in += len;
        if ( *in == '.' )
        {
            in++;
        }
        out += len + 1;
    }

    return -1;
}

/**
 * Find nearby answer structure
 */
static const struct dns_answer_t *dns_nearby_answer ( const unsigned char **pptr,
    const unsigned char *limit )
{
    const struct dns_answer_t *answer;
    const unsigned char *ptr;

    /* Get buffer pointer */
    ptr = *pptr;

    /* Skip DNS compressed hostname */
    while ( *ptr )
    {
        if ( ptr >= limit )
        {
            return NULL;
        }

        if ( *ptr >= 0xc0 )
        {
            ptr++;
            break;
        }
        ptr++;
    }

    /* Skip hostname terminator */
    ptr++;

    /* Check buffer bounds */
    if ( ptr + sizeof ( struct dns_answer_t ) > limit )
    {
        return NULL;
    }

    /* Map the result */
    answer = ( const struct dns_answer_t * ) ptr;

    /* Update buffer pointer */
    ptr += sizeof ( struct dns_answer_t ) + ntohs ( answer->rd_length );

    /* Recheck buffer bounds */
    if ( ptr > limit )
    {
        return NULL;
    }

    /* Update buffer pointer */
    *pptr = ptr;

    return answer;
}

/**
 * Decompress DNS name using packet iteration
 */
static ssize_t dns_decompress_name ( const unsigned char *in, size_t ipos,
    size_t inlen, unsigned char *out, size_t osize )
{
    size_t opos = 0;

    while ( ipos + 1 < inlen && in[ipos] )
    {
        if ( in[ipos] < 0xC0 )
        {
            if ( opos >= osize )
            {
                return -1;
            }

            out[opos++] = in[ipos++];

        } else
        {
            ipos = ( ( in[ipos] << 8 ) | in[ipos + 1] ) & 0x3FF;
        }
    }

    if ( opos >= osize )
    {
        return -1;
    }

    out[opos++] = 0;

    return opos;
}

/**
 * Resolve encoded hostname via Root Servers with depth check and retry
 */
static int dns_resolve_root ( const unsigned char *encoded, size_t enclen, size_t depth,
    unsigned int *addr );

/**
 * Perform DNS query with recursion
 */
static int dns_recursive_query ( const unsigned char *encoded, size_t enclen, size_t depth,
    unsigned int ns, unsigned int *addr )
{
    int sock;
    unsigned short i;
    unsigned short query_id;
    unsigned short ans_count;
    unsigned short auth_count;
    unsigned short add_count;
    unsigned int ns_addr;
    size_t query_len;
    size_t hostlen;
    size_t len;
    unsigned char *limit;
    const unsigned char *hostptr;
    const unsigned char *ptrbackup;
    const unsigned char *ptr;
    const unsigned int *addrptr;
    struct dns_header_t *header;
    struct dns_question_t *question;
    struct sockaddr_in dest;
    struct timeval tv = { 0 };
    const struct dns_answer_t *answer;
    unsigned char buffer[UDP_PKT_LEN_MAX];
    unsigned char hostbuf[DNS_NAME_SIZE_MAX];

    /* Check for recursion limit exceeded */
    if ( depth >= DNS_DEPTH_LIMIT )
    {
        return -1;
    }

    /* Get current time */
    gettimeofday ( &tv, NULL );

    /* Prepare DNS query */
    query_id = tv.tv_sec ^ tv.tv_usec;
    query_len = sizeof ( struct dns_header_t ) + enclen + sizeof ( struct dns_question_t );

    /* Check if buffer is big enough */
    if ( query_len > sizeof ( buffer ) )
    {
        return -1;
    }

    /* Prepare DNS query header */
    header = ( struct dns_header_t * ) buffer;
    header->id = htons ( query_id );
    header->qr = 0;     /* DNS query */
    header->opcode = 0; /* a standard dns query */
    header->aa = 0;     /* not authoritative */
    header->tc = 0;     /* message is not truncated */
    header->rd = 1;     /* recursion desired */
    header->ra = 0;     /* recursion is not available */
    header->z = 0;
    header->ad = 0;
    header->cd = 0;
    header->rcode = 0;
    header->q_count = htons ( 1 );      /* single question */
    header->ans_count = 0;
    header->auth_count = 0;
    header->add_count = 0;

    /* Put encoded hostname */
    memcpy ( buffer + sizeof ( struct dns_header_t ), encoded, enclen );

    /* Prepare DNS question */
    question = ( struct dns_question_t * ) ( buffer + sizeof ( struct dns_header_t ) + enclen );
    question->qtype = htons ( T_A );    /* set query type: A, MX, CNAME, NS, etc */
    question->qclass = htons ( 1 );     /* set query internet */

    /* Prepare socket address */
    dest.sin_family = AF_INET;
    dest.sin_port = htons ( 53 );
    dest.sin_addr.s_addr = ns;

    /* Create new UDP socket for the query */
    if ( ( sock = socket ( AF_INET, SOCK_DGRAM, IPPROTO_UDP ) ) < 0 )
    {
        return -1;
    }

    /* Set socket tx and rx timeouts */
    tv.tv_sec = DNS_SEND_TIMEOUT_SEC;
    tv.tv_usec = DNS_SEND_TIMEOUT_USEC;
    setsockopt ( sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof ( tv ) );
    tv.tv_sec = DNS_RECV_TIMEOUT_SEC;
    tv.tv_usec = DNS_RECV_TIMEOUT_USEC;
    setsockopt ( sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof ( tv ) );

    /* Send DNS query packet */
    if ( sendto ( sock, buffer, query_len, 0, ( struct sockaddr * ) &dest, sizeof ( dest ) ) < 0 )
    {
        close ( sock );
        return -1;
    }

    /* Wait for response */
    for ( i = 0; i < 255; i++ )
    {
        /* Receive DNS response packet */
        if ( ( ssize_t ) ( len =
                recvfrom ( sock, buffer, sizeof ( buffer ), 0, NULL, NULL ) ) <= 0 )
        {
            close ( sock );
            return -1;
        }

        /* Break on DNS query id and hostname match */
        if ( len >= query_len
            && ntohs ( header->id ) == query_id
            && !memcmp ( buffer + sizeof ( struct dns_header_t ), encoded, enclen ) )
        {
            break;
        }
    }

    /* Socket no longer needed */
    close ( sock );

    /* Prepare answer stats */
    ans_count = ntohs ( header->ans_count );
    auth_count = ntohs ( header->auth_count );
    add_count = ntohs ( header->add_count );

    /* Setup answer look up area */
    ptr = buffer + query_len;
    limit = buffer + len;

    /* Look up for A records in ANSWER section */
    for ( i = 0; i < ans_count; i++ )
    {
        if ( !( answer = dns_nearby_answer ( &ptr, limit ) ) )
        {
            return -1;
        }

        if ( ntohs ( answer->type ) == T_A
            && ntohs ( answer->rd_length ) == sizeof ( unsigned int ) )
        {
            addrptr =
                ( const unsigned int * ) ( ( const unsigned char * ) answer +
                sizeof ( struct dns_answer_t ) );
            *addr = *addrptr;
            return 0;
        }
    }

    /* Backup AUTHORITY section position */
    ptrbackup = ptr;

    /* Skip AUTHORITY section */
    for ( i = 0; i < auth_count; i++ )
    {
        if ( !( answer = dns_nearby_answer ( &ptr, limit ) ) )
        {
            return -1;
        }
    }

    /* Look up for A records in ADDITIONAL section */
    for ( i = 0; i < add_count; i++ )
    {
        if ( !( answer = dns_nearby_answer ( &ptr, limit ) ) )
        {
            break;
        }

        if ( ntohs ( answer->type ) == T_A
            && ntohs ( answer->rd_length ) == sizeof ( unsigned int ) )
        {
            addrptr =
                ( const unsigned int * ) ( ( const unsigned char * ) answer +
                sizeof ( struct dns_answer_t ) );

            if ( dns_recursive_query ( encoded, enclen, depth + 1, *addrptr, addr ) >= 0 )
            {
                return 0;
            }
        }
    }

    /* Restore AUTHORITY section position */
    ptr = ptrbackup;

    /* Look up for NS records in AUTHORITY section */
    for ( i = 0; i < header->auth_count; i++ )
    {
        if ( !( answer = dns_nearby_answer ( &ptr, limit ) ) )
        {
            return -1;
        }

        if ( ntohs ( answer->type ) == T_NS )
        {
            hostptr =
                ( const unsigned char * ) ( ( const unsigned char * ) answer +
                sizeof ( struct dns_answer_t ) );

            /* Resolve address with lower-level DNS server */
            if ( ( ssize_t ) ( hostlen =
                    dns_decompress_name ( buffer, hostptr - buffer, len, hostbuf,
                        sizeof ( hostbuf ) ) ) >= 0 )
            {
                if ( dns_resolve_root ( hostbuf, hostlen, depth + 1, &ns_addr ) >= 0 )
                {
                    if ( dns_recursive_query ( encoded, enclen, depth + 1, ns_addr, addr ) >= 0 )
                    {
                        return 0;
                    }
                }
            }
        }
    }

    /* Scan ANSWER section one more time */
    ptr = buffer + query_len;

    /* Look up for CNAME records in ANSWER section */
    for ( i = 0; i < ans_count; i++ )
    {
        if ( !( answer = dns_nearby_answer ( &ptr, limit ) ) )
        {
            return -1;
        }

        if ( ntohs ( answer->type ) == T_CNAME )
        {
            hostptr =
                ( const unsigned char * ) ( ( const unsigned char * ) answer +
                sizeof ( struct dns_answer_t ) );

            /* Resolve address with lower-level DNS server */
            if ( ( ssize_t ) ( hostlen =
                    dns_decompress_name ( buffer, hostptr - buffer, len, hostbuf,
                        sizeof ( hostbuf ) ) ) >= 0 )
            {
                if ( dns_resolve_root ( hostbuf, hostlen, depth + 1, addr ) >= 0 )
                {
                    return 0;
                }
            }
        }
    }

    /* Nothing useful found */
    return -1;
}

/**
 * Resolve encoded hostname via Root Servers with depth check and retry
 */
static int dns_resolve_root ( const unsigned char *encoded, size_t enclen, size_t depth,
    unsigned int *addr )
{
    size_t i;
    size_t ns_seed;
    unsigned int ns;
    struct timeval tv = { 0 };
    /* Seed NS selection */
    gettimeofday ( &tv, NULL );
    ns_seed = tv.tv_sec ^ tv.tv_usec;

    for ( i = 0; i < DNS_N_SERVERS; i++ )
    {
        ns = htonl ( dns_servers[( ns_seed + i ) % DNS_N_SERVERS] );

        if ( dns_recursive_query ( encoded, enclen, depth, ns, addr ) >= 0 )
        {
            return 0;
        }
    }

    return -1;
}

/**
 * Resolve hostname into IPv4 address
 */
int nsaddr ( const char *hostname, unsigned int *addr )
{
    unsigned char encoded[DNS_NAME_SIZE_MAX];

    if ( dns_encode_hostname ( hostname, encoded, sizeof ( encoded ) ) < 0 )
    {
        return -1;
    }

    return dns_resolve_root ( encoded, strlen ( hostname ) + 2, 0, addr );
}
