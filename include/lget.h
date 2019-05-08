/* ------------------------------------------------------------------
 * Lget - Project Shared Header
 * ------------------------------------------------------------------ */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef LGET_H
#define LGET_H

/**
 * Resolve hostname into IPv4 address
 */
extern int nsaddr ( const char *hostname, unsigned int *address );

#endif
