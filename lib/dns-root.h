/* ------------------------------------------------------------------
 * LibDNS - Portable DNS Client
 * ------------------------------------------------------------------ */

#ifndef DNS_ROOT_H
#define DNS_ROOT_H

/**
 * Address list of DNS Root Servers
 */
static const unsigned int dns_servers[] = {
    0x08080808, /* Google DNS: 8.8.8.8 */
    0x08080404, /* Google DNS: 8.8.4.4 */
    0x08080808, /* Google DNS: 8.8.8.8 */
    0x08080404, /* Google DNS: 8.8.4.4 */
    0x08080808, /* Google DNS: 8.8.8.8 */
    0x08080404  /* Google DNS: 8.8.4.4 */
};

#endif
