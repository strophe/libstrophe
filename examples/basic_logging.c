/* basic.c
** libstrophe XMPP client library -- basic usage example
**
** Copyright (C) 2005 OGG, LCC. All rights reserved.
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This software is distributed under license and may not be copied,
**  modified or distributed except as expressly authorized under the
**  terms of the license contained in the file LICENSE.txt in this
**  distribution.
*/

#include <stdio.h>

#include <strophe.h>

void log_handler(void * const userdata, 
		 const xmpp_log_level_t level,
		 const char * const area,
		 const char * const msg)
{
    fprintf(stderr, "%s %s %s\n", area, xmpp_log_level_name[level], msg);
}

void conn_handler(xmpp_conn_t * const conn, const xmpp_conn_event_t status, 
		  const int error, xmpp_stream_error_t * const stream_error,
		  void * const userdata)
{
    xmpp_ctx_t *ctx = (xmpp_ctx_t *)userdata;

    if (status == XMPP_CONN_CONNECT) {
	fprintf(stderr, "DEBUG: connected\n");
	xmpp_disconnect(conn);
    }
    else {
	fprintf(stderr, "DEBUG: disconnected\n");
	xmpp_stop(ctx);
    }
}

int main(int argc, char **argv)
{
    xmpp_ctx_t *ctx;
    xmpp_conn_t *conn;
    xmpp_log_t log;
    char *jid, *pass;
    char *server;

    if ((argc < 3) || (argc > 4)) {
	fprintf(stderr, "Usage: basic <jid> <pass> <server>\n\n");
	return 1;
    }
    
    jid = argv[1];
    pass = argv[2];
    if (argc >= 4) server = argv[3];
    else server = NULL;
    
    /* init library */
    xmpp_initialize();

    /* create a context */
    log.handler = log_handler;
    log.userdata = NULL;
    ctx = xmpp_ctx_new(NULL, &log);

    /* create a connection */
    conn = xmpp_conn_new(ctx);

    /* setup authentication information */
    xmpp_conn_set_jid(conn, argv[1]);
    xmpp_conn_set_pass(conn, argv[2]);

    /* initiate connection */
    xmpp_connect_client(conn, argv[3], conn_handler, ctx);

    /* start the event loop */
    xmpp_run(ctx);

    /* release our connection and context */
    xmpp_conn_release(conn);
    xmpp_ctx_free(ctx);

    xmpp_shutdown();

    return 0;
}
