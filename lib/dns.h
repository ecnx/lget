/* ------------------------------------------------------------------
 * LibDNS - Portable DNS Client
 * ------------------------------------------------------------------ */

#include <arpa/inet.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef DNS_H
#define DNS_H

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
 * DNS socket timeouts
 */
#define DNS_SEND_TIMEOUT_SEC 3
#define DNS_SEND_TIMEOUT_USEC 0
#define DNS_RECV_TIMEOUT_SEC 3
#define DNS_RECV_TIMEOUT_USEC 0

/**
 * Maximum size of an UDP packet
 */
#define UDP_PKT_LEN_MAX 65536

/**
 * DNS resolve settings
 */
#define DNS_DEPTH_LIMIT 16
#define DNS_NAME_SIZE_MAX 256

/**
 * DNS header structure
 */
struct dns_header_t
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
} __attribute__( ( packed ) );

/**
 * DNS query structure
 */
struct dns_question_t
{
    unsigned short qtype;
    unsigned short qclass;
} __attribute__( ( packed ) );

/**
 * DNS answer structure
 */
struct dns_answer_t
{
    /* name */
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short rd_length;
    /* rdata */
} __attribute__( ( packed ) );

/**
 * Resolve hostname into IPv4 address
 */
extern int nsaddr ( const char *hostname, unsigned int *addr );

#endif
