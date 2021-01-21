/* ------------------------------------------------------------------
 * Lget - Main Program File
 * ------------------------------------------------------------------ */

#include "lget.h"

/**
 * Show program usage message
 */
static void show_usage ( void )
{
    printf ( "usage: lget [-s5h|--socks5h] hostname:port url file\n" );
}

/*
 * Main program task
 */
int lget_task ( const char *url, const char *filepath, const struct socks5h_t *socks5h )
{
    struct socks5_t socks5;

    /* Setup socks5 details if needed */
    if ( socks5h )
    {
        if ( nsaddr ( socks5h->hostname, &socks5.addr ) < 0 )
        {
            perror ( "nsaddr" );
            return -1;
        }
        socks5.port = socks5h->port;
    }

    /* Download file over http protocol */
    if ( http_get ( url, filepath, socks5h ? &socks5 : NULL ) < 0 )
    {
        return -1;
    }

    return 0;
}

/*
 * Main program function
 */
int main ( int argc, char *argv[] )
{
    int argoff = 0;
    int use_socks5h = 0;
    struct socks5h_t socks5h;

    if ( argc < 3 )
    {
        show_usage (  );
        return 1;
    }

    if ( !strcmp ( argv[argoff + 1], "-s5h" ) || !strcmp ( argv[argoff + 1], "--socks5h" ) )
    {

        if ( argc < 5 )
        {
            show_usage (  );
            return 1;
        }

        if ( parse_host ( argv[2], socks5h.hostname, sizeof ( socks5h.hostname ),
                &socks5h.port ) < 0 )
        {
            show_usage (  );
            return 1;
        }

        use_socks5h = 1;
        argoff += 2;
    }

    if ( lget_task ( argv[argoff + 1], argv[argoff + 2], use_socks5h ? &socks5h : NULL ) < 0 )
    {
        return 1;
    }

    return 0;
}
