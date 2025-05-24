/* SPDX-License-Identifier: MIT OR GPL-3.0-only */
/* vcard.c
 * strophe XMPP client library -- vCard example
 *
 * Copyright (C) 2016 Dmitry Podgorny <pasis.ua@gmail.com>
 *
 *  This software is provided AS-IS with no warranty, either express
 *  or implied.
 *
 *  This program is dual licensed under the MIT or GPLv3 licenses.
 */

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <strophe.h>
#ifndef _WIN32
#include <libgen.h> /* basename */
#else
#define strtok_r strtok_s
#define basename(x) "vcard"
#endif

typedef struct {
    xmpp_ctx_t *ctx;
    const char *recipient;
    const char *img_path;
} vcard_t;

typedef void (*vcard_cb_t)(vcard_t *, xmpp_stanza_t *);

#define REQ_TIMEOUT 5000
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

static void vcard_photo(vcard_t *vc, xmpp_stanza_t *stanza)
{
    xmpp_stanza_t *tmp;
    char *s;
    char *tok;
    char *saveptr = NULL;
    char *copy;
    unsigned char *img;
    size_t img_size;
    size_t written;
    FILE *fd;

    tmp = xmpp_stanza_get_child_by_name(stanza, "TYPE");
    assert(tmp != NULL);
    s = xmpp_stanza_get_text(tmp);
    assert(s != NULL);
    printf("PHOTO: %s, saving to file %s\n", s, vc->img_path);
    xmpp_free(vc->ctx, s);

    tmp = xmpp_stanza_get_child_by_name(stanza, "BINVAL");
    assert(tmp != NULL);
    s = xmpp_stanza_get_text(tmp);
    assert(s != NULL);

    /* remove \n and \r */
    copy = (char *)malloc(strlen(s) + 1);
    assert(copy != NULL);
    copy[0] = '\0';
    tok = strtok_r(s, "\n\r", &saveptr);
    while (tok != NULL) {
        strcat(copy, tok);
        tok = strtok_r(NULL, "\n\r", &saveptr);
    }

    xmpp_base64_decode_bin(vc->ctx, copy, strlen(copy), &img, &img_size);
    assert(img != NULL);

    fd = fopen(vc->img_path, "w");
    assert(fd != NULL);
    written = fwrite(img, 1, img_size, fd);
    if (written < img_size)
        printf("Saving photo failed\n");
    fclose(fd);

    free(copy);
    xmpp_free(vc->ctx, s);
    xmpp_free(vc->ctx, img);
}

static void
vcard_print_string(vcard_t *vc, xmpp_stanza_t *stanza, const char *info)
{
    char *s = xmpp_stanza_get_text(stanza);

    assert(s != NULL);
    printf("%s: %s\n", info, s);
    xmpp_free(vc->ctx, s);
}

static void vcard_bday(vcard_t *vc, xmpp_stanza_t *stanza)
{
    vcard_print_string(vc, stanza, "Birthday");
}

static void vcard_desc(vcard_t *vc, xmpp_stanza_t *stanza)
{
    vcard_print_string(vc, stanza, "Description");
}

static void vcard_email(vcard_t *vc, xmpp_stanza_t *stanza)
{
    xmpp_stanza_t *userid = xmpp_stanza_get_child_by_name(stanza, "USERID");

    if (userid != NULL)
        vcard_print_string(vc, userid, "E-mail");
}

static void vcard_fn(vcard_t *vc, xmpp_stanza_t *stanza)
{
    vcard_print_string(vc, stanza, "Full name");
}

static void vcard_name(vcard_t *vc, xmpp_stanza_t *stanza)
{
    xmpp_stanza_t *name = xmpp_stanza_get_child_by_name(stanza, "GIVEN");
    xmpp_stanza_t *family = xmpp_stanza_get_child_by_name(stanza, "FAMILY");

    if (name != NULL)
        vcard_print_string(vc, name, "Given name");
    if (family != NULL)
        vcard_print_string(vc, family, "Family name");
}

static void vcard_nick(vcard_t *vc, xmpp_stanza_t *stanza)
{
    vcard_print_string(vc, stanza, "Nickname");
}

static void vcard_url(vcard_t *vc, xmpp_stanza_t *stanza)
{
    vcard_print_string(vc, stanza, "URL");
}

static vcard_cb_t vcard_cb_get(xmpp_stanza_t *stanza)
{
    vcard_cb_t cb = NULL;
    const char *tag;
    size_t i;

    static struct {
        const char *tag;
        vcard_cb_t cb;
    } vcard_tbl[] = {
        {"PHOTO", vcard_photo},   {"BDAY", vcard_bday}, {"DESC", vcard_desc},
        {"EMAIL", vcard_email},   {"FN", vcard_fn},     {"N", vcard_name},
        {"NICKNAME", vcard_nick}, {"URL", vcard_url},
    };

    tag = xmpp_stanza_get_name(stanza);
    if (tag == NULL)
        goto exit;

    for (i = 0; i < ARRAY_SIZE(vcard_tbl); ++i) {
        if (strcmp(tag, vcard_tbl[i].tag) == 0) {
            cb = vcard_tbl[i].cb;
            break;
        }
    }

exit:
    return cb;
}

static int timedout(xmpp_conn_t *conn, void *userdata)
{
    (void)userdata;

    fprintf(stderr, "Timeout reached.\n");
    xmpp_disconnect(conn);

    return 0;
}

static int recv_vcard(xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata)
{
    vcard_t *vc = userdata;
    vcard_cb_t cb;
    xmpp_stanza_t *child;
    char *s;
    size_t s_size;
    int rc;

    printf("Received vCard.\n\n");

    child = xmpp_stanza_get_child_by_name(stanza, "error");
    if (child != NULL) {
        rc = xmpp_stanza_to_text(child, &s, &s_size);
        assert(rc == XMPP_EOK);
        printf("Error returned: %s.\n", s);
        xmpp_free(vc->ctx, s);
        goto exit;
    }

    child = xmpp_stanza_get_child_by_name(stanza, "vCard");
    assert(child != NULL);
    child = xmpp_stanza_get_children(child);
    while (child != NULL) {
        cb = vcard_cb_get(child);
        if (cb != NULL)
            cb(vc, child);
        child = xmpp_stanza_get_next(child);
    }

exit:
    xmpp_disconnect(conn);

    return 0;
}

static void send_vcard_req(xmpp_conn_t *conn, const char *to, const char *id)
{
    printf("Requesting vCard from %s.\n", to);
    xmpp_send_raw_string(conn,
                         "<iq from='%s' to='%s' type='get' id='%s'>"
                         "<vCard xmlns='vcard-temp'/></iq>",
                         xmpp_conn_get_bound_jid(conn), to, id);
}

static void conn_handler(xmpp_conn_t *conn,
                         xmpp_conn_event_t status,
                         int error,
                         xmpp_stream_error_t *stream_error,
                         void *userdata)
{
    vcard_t *vc = userdata;

    if (status == XMPP_CONN_CONNECT) {
        send_vcard_req(conn, vc->recipient, "vc1");
        xmpp_id_handler_add(conn, recv_vcard, "vc1", vc);
        xmpp_timed_handler_add(conn, timedout, REQ_TIMEOUT, NULL);
    } else {
        if (error != 0)
            fprintf(stderr, "Disconnected with error=%d.\n", error);
        if (stream_error != NULL)
            fprintf(stderr, "Stream error type=%d text=%s.\n",
                    stream_error->type, stream_error->text);
        xmpp_stop(vc->ctx);
    }
}

int main(int argc, char **argv)
{
    xmpp_log_t *log;
    xmpp_ctx_t *ctx;
    xmpp_conn_t *conn;
    const char *jid;
    const char *pass;
    char *prog;
    vcard_t vcard;

    if (argc < 4 || argc > 5) {
        prog = argc > 0 ? strdup(argv[0]) : NULL;
        printf("Usage: %s <login-jid> <password> <recipient-jid> "
               "[image-file]\n\n",
               prog == NULL ? "vcard" : basename(prog));
        printf("If vCard contains a photo it will be stored to "
               "image-file. If you don't provide the image-file "
               "default filename will be generated.\n");
        free(prog);
        return 1;
    }

    jid = argv[1];
    pass = argv[2];
    vcard.recipient = argv[3];
    vcard.img_path = argc > 4 ? argv[4] : "vcard.jpg";

    xmpp_initialize();
    log = xmpp_get_default_logger(XMPP_LEVEL_INFO);
    ctx = xmpp_ctx_new(NULL, log);
    conn = xmpp_conn_new(ctx);
    xmpp_conn_set_jid(conn, jid);
    xmpp_conn_set_pass(conn, pass);
    vcard.ctx = ctx;
    xmpp_connect_client(conn, NULL, 0, conn_handler, &vcard);
    xmpp_run(ctx);
    xmpp_conn_release(conn);
    xmpp_ctx_free(ctx);
    xmpp_shutdown();

    return 0;
}
