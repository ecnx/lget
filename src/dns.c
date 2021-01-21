/* ------------------------------------------------------------------
 * Lget - Simple DNS Support
 * ------------------------------------------------------------------ */

#include "lget.h"

#ifndef SYSTEM_RESOLVER
#include <endian.h>

/**
 * DNS resource records types list
 */
#define T_A         1   /* IPv4 address */
#define T_NS        2   /* Nameserver */
#define T_CNAME     5   /* Canonical name */
#define T_SOA       6   /* Start of authority zone */
#define T_PTR       12  /* Domain name pointer */
#define T_MX        15  /* Mail server */

/**
 * DNS timeouts constants
 */
#define DNS_SEND_TIMEOUT_SEC 3
#define DNS_SEND_TIMEOUT_USEC 0
#define DNS_RECV_TIMEOUT_SEC 3
#define DNS_RECV_TIMEOUT_USEC 0

/**
 * Maximal size of an UDP packet
 */
#define UDP_PKT_LEN_MAX 65536

/**
 * Maximal recurses count
 */
#define DNS_ATTEMPTS_MAX 32

/**
 * DNS header structure
 */
#define DNS_NAME_SIZE_MAX 256

struct dns_header
{
    unsigned short id;          /* identification number */

#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned char rd:1;         /* recursion desired */
    unsigned char tc:1;         /* truncated message */
    unsigned char aa:1;         /* authoritive answer */
    unsigned char opcode:4;     /* purpose of message */
    unsigned char qr:1;         /* query/response flag */
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned char qr:1;         /* query/response flag */
    unsigned char opcode:4;     /* purpose of message */
    unsigned char aa:1;         /* authoritive answer */
    unsigned char tc:1;         /* truncated message */
    unsigned char rd:1;         /* recursion desired */
#else
#error "Endian not set"
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned char rcode:4;      /* response code */
    unsigned char cd:1;         /* checking disabled */
    unsigned char ad:1;         /* authenticated data */
    unsigned char z:1;          /* reserved for future use */
    unsigned char ra:1;         /* recursion available */
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned char ra:1;         /* recursion available */
    unsigned char z:1;          /* reserved for future use */
    unsigned char ad:1;         /* authenticated data */
    unsigned char cd:1;         /* checking disabled */
    unsigned char rcode:4;      /* response code */
#else
#error "Endian not set"
#endif

    unsigned short q_count;     /* number of question entries */
    unsigned short ans_count;   /* number of answer entries */
    unsigned short auth_count;  /* number of authority entries */
    unsigned short add_count;   /* number of resource entries */
};

/**
 * Constant sized fields of query structure
 */
struct dns_question
{
    unsigned short qtype;
    unsigned short qclass;
};

/**
 * Constant sized fields of the resource record structure
 */
#pragma pack(push, 1)
struct r_data
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)

/**
 * Address list of DNS Root Servers
 */
static const unsigned int dns_servers[] = {
    0xc6290004, /* a.root-servers.net 198.41.0.4, 2001:503:ba3e::2:30 VeriSign, Inc. */
    0xc7090ec9, /* b.root-servers.net 199.9.14.201, 2001:500:200::b University of Southern California (ISI) */
    0xc021040c, /* c.root-servers.net 192.33.4.12, 2001:500:2::c Cogent Communications */
    0xc7075b0d, /* d.root-servers.net 199.7.91.13, 2001:500:2d::d University of Maryland */
    0xc0cbe60a, /* e.root-servers.net 192.203.230.10, 2001:500:a8::e NASA (Ames Research Center) */
    0xc00505f1, /* f.root-servers.net 192.5.5.241, 2001:500:2f::f Internet Systems Consortium, Inc. */
    0xc0702404, /* g.root-servers.net 192.112.36.4, 2001:500:12::d0d US Department of Defense (NIC) */
    0xc661be35, /* h.root-servers.net 198.97.190.53, 2001:500:1::53 US Army (Research Lab) */
    0xc0249411, /* i.root-servers.net 192.36.148.17, 2001:7fe::53 Netnod */
    0xc03a801e, /* j.root-servers.net 192.58.128.30, 2001:503:c27::2:30 VeriSign, Inc. */
    0xc1000e81, /* k.root-servers.net 193.0.14.129, 2001:7fd::1 RIPE NCC */
    0xc707532a, /* l.root-servers.net 199.7.83.42, 2001:500:9f::42 ICANN */
    0xca0c1b21  /* m.root-servers.net 202.12.27.33, 2001:dc3::35 WIDE Project */
};

/**
 * Format host like www.example.com to 3www7example3com
 */
static int dns_format_host ( const char *host, unsigned char *dns, size_t dns_size )
{
    size_t lock;
    size_t i;
    size_t len;

    /* Two bytes extra for prefix and NULL */
    if ( dns_size <= ( len = strlen ( host ) ) + 1 )
    {
        errno = ENOBUFS;
        return -1;
    }

    /* Insert length prefix before each part */
    for ( i = 0, lock = 0; i <= len; i++ )
    {
        /* Immit normal characters */
        if ( host[i] != '.' && i != len )
        {
            continue;
        }

        /* Place substring length */
        *dns++ = i - lock;

        /* Copy substring characters */
        while ( lock < i )
        {
            *dns++ = host[lock++];
        }
        lock++;
    }

    /* Place NULL terminator at the end of buffer */
    *dns++ = '\0';

    return 0;
}

/**
 * Find offset of nearby response data structure
 */
static size_t dns_r_data_offset ( const unsigned char *buffer, size_t len, size_t offset )
{
    size_t i;

    /* Skip DNS formatted host name bytes */
    for ( i = 0; buffer[offset] != '\0' && offset < len; i++ )
    {
        /* Stop if an offset has been found */
        if ( buffer[offset + i] >= 0xC0 )
        {
            /* Each offset is two bytes wide */
            return i + 2;
        }
    }

    /* Also count up zero character at the end */
    return i + 1;
}

/**
 * Decompress DNS name using packet iteration
 */
static size_t dns_decompress_name ( const unsigned char *buffer, size_t len, size_t offset,
    unsigned char *name, size_t name_len )
{
    size_t i = 0;

    /* Decompress name from DNS response */
    while ( offset < len && i < name_len )
    {
        /* Perform a jump if an offset is found */
        if ( buffer[offset] >= 0xC0 )
        {
            offset = ( ( buffer[offset] << 8 ) + buffer[offset + 1] ) & 0x3FF;
            continue;
        }

        /* Place normal characters to name buffer */
        if ( ( name[i++] = buffer[offset++] ) == '\0' )
        {
            break;
        }
    }

    return i;
}

/**
 * Perform a DNS query by sending a packet
 */
static int ngethostbyname ( const unsigned char *host, size_t host_len, size_t *attempts,
    unsigned int *addr )
{
    int sock;
    unsigned short i;

    size_t qinfo_offset;
    size_t query_len;
    size_t offset;
    size_t auth_offset;
    size_t len;
    size_t ns_name_len;

    socklen_t dest_len;
    struct sockaddr_in dest;
    struct dns_header *dns = NULL;
    struct dns_question *qinfo = NULL;
    struct r_data *resource;
    struct timeval tv;

    unsigned char buffer[UDP_PKT_LEN_MAX];
    unsigned char ns_name[DNS_NAME_SIZE_MAX];

    /* Host size must be at least three bytes */
    if ( host_len < 3 )
    {
        errno = EINVAL;
        return -1;
    }

    /* UDP packet for DNS queries */
    if ( ( sock = socket ( AF_INET, SOCK_DGRAM, IPPROTO_UDP ) ) < 0 )
    {
        return -1;
    }

    /* Set socket send timeout */
    tv.tv_sec = DNS_SEND_TIMEOUT_SEC;
    tv.tv_usec = DNS_SEND_TIMEOUT_USEC;
    setsockopt ( sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof ( tv ) );

    /* Set socket receive timeout */
    tv.tv_sec = DNS_RECV_TIMEOUT_SEC;
    tv.tv_usec = DNS_RECV_TIMEOUT_USEC;
    setsockopt ( sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof ( tv ) );

    /* Prepare destination address */
    dest.sin_family = AF_INET;
    dest.sin_port = htons ( 53 );

    /* Obtani current time */
    gettimeofday ( &tv, NULL );

    /* Select random DNS server */
    dest.sin_addr.s_addr =
        htonl ( dns_servers[tv.tv_usec % ( sizeof ( dns_servers ) / sizeof ( unsigned int ) )] );

  recurse:

    /* Validate attempts count */
    if ( *attempts > DNS_ATTEMPTS_MAX )
    {
        close ( sock );
        errno = EAGAIN;
        return -1;
    }

    /* Set the DNS structure to standard queries */
    dns = ( struct dns_header * ) &buffer;
    dns->id = htons ( tv.tv_usec );
    dns->qr = 0;        /* DNS query */
    dns->opcode = 0;    /* a standard dns query */
    dns->aa = 0;        /* not authoritative */
    dns->tc = 0;        /* message is not truncated */
    dns->rd = 1;        /* recursion desired */
    dns->ra = 0;        /* recursion is not available */
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons ( 1 ); /* single question */
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;

    /* Validate host buffer size */
    if ( host_len > sizeof ( buffer ) - sizeof ( struct dns_header ) )
    {
        close ( sock );
        errno = ENOBUFS;
        return -1;
    }

    /* Copy host to packet buffer area */
    memcpy ( buffer + sizeof ( struct dns_header ), host, host_len );

    /* Calculate query info offset */
    qinfo_offset = sizeof ( struct dns_header ) + host_len;
    qinfo = ( struct dns_question * ) ( buffer + qinfo_offset );

    /* Set query type: A, MX, CNAME, NS, etc */
    qinfo->qtype = htons ( T_A );

    /* Set query internet */
    qinfo->qclass = htons ( 1 );

    /* Calulculate query length */
    query_len = qinfo_offset + sizeof ( struct dns_question );

    /* Send DNS query packet */
    if ( sendto ( sock, buffer, query_len, 0, ( struct sockaddr * ) &dest, sizeof ( dest ) ) < 0 )
    {
        close ( sock );
        return -1;
    }

    /* Set socket address length */
    dest_len = sizeof ( dest );

    /* Receive the answer from DNS server */
    if ( ( ssize_t ) ( len =
            recvfrom ( sock, buffer, sizeof ( buffer ), 0, ( struct sockaddr * ) &dest,
                &dest_len ) ) < 0 )
    {
        ( *attempts )++;
        goto recurse;
    }

    /* Move ahead of the DNS header and the query field */
    offset = query_len;

    /* Lookup for server address in DNS answers */
    for ( i = 0; i < ntohs ( dns->ans_count ) && offset < len; i++ )
    {
        /* Load and assert following response data offset */
        if ( ( offset += dns_r_data_offset ( buffer, len, offset ) ) > len )
        {
            break;
        }

        /* Load resource pointer and skip r_data bytes */
        resource = ( struct r_data * ) ( buffer + offset );

        /* Skip r_data structure bytes */
        if ( ( offset += sizeof ( struct r_data ) ) >= len )
        {
            break;
        }

        /* Filter for type A records */
        if ( ntohs ( resource->type ) == T_A )
        {
            memcpy ( addr, buffer + offset, sizeof ( unsigned int ) );
            close ( sock );
            return 0;
        }

        /* Filter for type CNAME records */
        if ( ntohs ( resource->type ) == T_CNAME )
        {
            /* Decompress nameserver name */
            ns_name_len = dns_decompress_name ( buffer, len, offset, ns_name, sizeof ( ns_name ) );

            /* Obtain address of DNS sub-server */
            ( *attempts )++;
            if ( !ngethostbyname ( ns_name, ns_name_len, attempts, addr ) )
            {
                close ( sock );
                return 0;
            }
        }

        /* Load and assert following response data offset */
        offset += dns_r_data_offset ( buffer, len, offset );
    }

    /* Save authoritative section offset */
    auth_offset = offset;

    /* Skip all authoritative records available */
    for ( i = 0; i < ntohs ( dns->auth_count ) && offset < len; i++ )
    {
        /* Load and assert following response data offset */
        if ( ( offset += dns_r_data_offset ( buffer, len, offset ) ) > len )
        {
            break;
        }

        /* Skip r_data structure bytes */
        if ( ( offset += sizeof ( struct r_data ) ) >= len )
        {
            break;
        }

        /* Load and assert following response data offset */
        offset += dns_r_data_offset ( buffer, len, offset );
    }

    /* Lookup for additional type A records */
    for ( i = 0; i < ntohs ( dns->add_count ) && offset < len; i++ )
    {
        /* Load and assert following response data offset */
        if ( ( offset += dns_r_data_offset ( buffer, len, offset ) ) > len )
        {
            break;
        }

        /* Load resource pointer and skip r_data bytes */
        resource = ( struct r_data * ) ( buffer + offset );

        /* Skip r_data structure bytes */
        if ( ( offset += sizeof ( struct r_data ) ) >= ( size_t ) len )
        {
            break;
        }

        /* Recurse DNS query if type A record is found */
        if ( ntohs ( resource->type ) == T_A )
        {
            memcpy ( &dest.sin_addr.s_addr, buffer + offset, sizeof ( unsigned int ) );
            ( *attempts )++;
            goto recurse;
        }

        /* Load and assert following response data offset */
        offset += dns_r_data_offset ( buffer, len, offset );
    }

    /* Recall authoritative section offset */
    offset = auth_offset;

    /* Skip all authoritative records available */
    for ( i = 0; i < ntohs ( dns->auth_count ) && offset < len; i++ )
    {
        /* Load and assert following response data offset */
        if ( ( offset += dns_r_data_offset ( buffer, len, offset ) ) > len )
        {
            break;
        }

        /* Load resource pointer and skip r_data bytes */
        resource = ( struct r_data * ) ( buffer + offset );

        /* Skip r_data structure bytes */
        if ( ( offset += sizeof ( struct r_data ) ) >= len )
        {
            break;
        }

        /* Filter nameservers records */
        if ( ntohs ( resource->type ) != T_NS )
        {
            /* Load and assert following response data offset */
            offset += dns_r_data_offset ( buffer, len, offset );
            continue;
        }

        /* Decompress nameserver name */
        ns_name_len = dns_decompress_name ( buffer, len, offset, ns_name, sizeof ( ns_name ) );

        /* Obtain address of DNS sub-server */
        ( *attempts )++;
        if ( ngethostbyname ( ns_name, ns_name_len, attempts, &dest.sin_addr.s_addr ) < 0 )
        {
            close ( sock );
            return -1;
        }

        /* Recurse DNS query if type A record is found */
        goto recurse;
    }

    /* No address has been found */
    close ( sock );
    errno = ENODATA;
    return -1;
}

/**
 * Resolve hostname into IPv4 address
 */
int nsaddr ( const char *hostname, unsigned int *addr )
{
    size_t attempts = 0;
    unsigned char host[DNS_NAME_SIZE_MAX];

    if ( inet_pton ( AF_INET, hostname, addr ) > 0 )
    {
        return 0;
    }

    if ( dns_format_host ( hostname, host, sizeof ( host ) ) < 0 )
    {
        return -1;
    }

    return ngethostbyname ( host, strlen ( hostname ) + 2, &attempts, addr );
}

#else

/**
 * Resolve hostname into IPv4 address
 */
int nsaddr ( const char *server_name, unsigned int *address )
{
    struct hostent *he;
    struct in_addr **addr_list;

    /* Query host addess */
    if ( !( he = gethostbyname ( server_name ) ) )
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
    *address = ( *addr_list )[0].s_addr;

    return 0;
}

#endif
