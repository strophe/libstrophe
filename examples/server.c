
#include <stdio.h>
#include <string.h>
#include <strophe.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

int message_handler(xmpp_conn_t * const conn, xmpp_stanza_t * const stanza,
                    void * const userdata)
{
    xmpp_ctx_t *ctx = (xmpp_ctx_t *)userdata;
    xmpp_stanza_t *success;

    if (strcmp(xmpp_stanza_get_name(stanza), "auth") == 0) {
        success = xmpp_stanza_new(ctx);
        xmpp_stanza_set_name(success, "success");
        xmpp_stanza_set_ns(success, XMPP_NS_SASL);
        xmpp_send(conn, success);
        xmpp_stanza_release(success);
    } else
        xmpp_disconnect(conn);

    return 1;
}

void server_handler(xmpp_server_t * const srv, xmpp_conn_t * const conn,
                    const xmpp_server_event_t event, const int error,
                    void * const userdata)
{
    xmpp_ctx_t *ctx = (xmpp_ctx_t *)userdata;

    static char *attrs[] = {
        "xmlns", XMPP_NS_CLIENT, "xmlns:stream", XMPP_NS_STREAMS,
        "id", "0123456789", "from", "127.0.0.1", "version", "1.0",
        "xml:lang", "en",
    };

    switch (event) {
    case XMPP_SERVER_ACCEPT:
        printf("Event XMPP_SERVER_ACCEPT\n");
        break;
    case XMPP_SERVER_OPEN_STREAM:
        printf("Event XMPP_SERVER_OPEN_STREAM\n");
        xmpp_handler_add(conn, message_handler, NULL, NULL, NULL, ctx);
        xmpp_conn_open_stream(conn, attrs, ARRAY_SIZE(attrs));
        xmpp_send_raw_string(conn,
                "<stream:features>"
                "<mechanisms xmlns=\"%s\"><mechanism>PLAIN</mechanism>"
                "</mechanisms></stream:features>", XMPP_NS_SASL);
        break;
    case XMPP_SERVER_DISCONNECT:
        printf("Event XMPP_SERVER_DISCONNECT\n");
        xmpp_stop(ctx);
        break;
    default:
        printf("Unknown event\n");
        break;
    }
}

int main()
{
    xmpp_ctx_t *ctx;
    xmpp_log_t *log;
    xmpp_server_t *srv;

    xmpp_initialize();
    log = xmpp_get_default_logger(XMPP_LEVEL_DEBUG);
    ctx = xmpp_ctx_new(NULL, log);
    srv = xmpp_server_new(ctx);
    xmpp_server_listen(srv, 0, server_handler, ctx);

    xmpp_run(ctx);

    xmpp_server_stop(srv);
    xmpp_server_free(srv);
    xmpp_ctx_free(ctx);
    xmpp_shutdown();

    return 0;
}
