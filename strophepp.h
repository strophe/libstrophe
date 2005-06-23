#ifndef __LIBSTROPHE_STROPHEPP_H__
#define __LIBSTROPHE_STROPHEPP_H__

#include "strophe.h"

namespace XMPP {

    typedef void (*alloc_handler)(const size_t size);
    typedef void (*free_handler)(void *p);
    typedef void (*realloc_handler)(void *p const size_t size);

    class Context {
    private:
	xmpp_ctx_t *ctx;

    public:
	Context();
	virtual ~Context();

	void setAlloc(alloc_handler handler);
	void setRealloc(realloc_handler handler);
	void setFree(free_handler handler);
	void setLogger(xmpp_log_handler handler, void * const userdata);
    }

    class Connection {
    private:
	xmpp_conn_t *conn;

    public:
	Connection();
	virtual ~Connection();
	Connection *clone();

	const char *getJID();
	void setJID(const char * const jid);
	const char *getPass();
	void setPass(const char * const pass);
	bool connectClient(const char * const domain,
			   xmpp_conn_handler callback,
			   void * const userdata);
	void disconnect();
	void send(Stanza *stanza);

	void addTimedHandler(xmpp_timed_handler handler,
			     const unsigned long perdio,
			     void * const userdata);
	void deleteTimedHandler(xmpp_timed_handler handler);
	void addHandler(xmpp_handler handler,
			const char * const ns,
			const char * const name,
			const char * const type,
			void * const userdata);
	void deleteHandler(xmpp_handler handler);
	void addIdHandler(xmpp_handler handler,
			  const char * const id,
			  void * const userdata);
	void deleteIdHandler(xmpp_handler handler);
    }

    class Stanza {
    private:
	xmpp_stanza_t *stanza;

    public:
	Stanza();
	virtual ~Stanza();
	Stanza *clone();
	Stanza *copy();
	
	int toText(const char ** const buf, size_t * const buflen);
	Stanza *getChildren();
	Stanza *getChildByName(const char * const name);
	Stanza *getNext();
        char *getAttribute(const char * const name);
	char *getNamespace();
	char *getText();
	char *getName();
	void addChild(Stanza *child);
	void setNamespace(const char * const ns);
	void setAttribute(const char * const key, const char * const value);
	void setName(const char * const name);
	void setText(const char * const text);
	void setText(const char * const text, const size_t size);
	char *getType();
	char *getId();
	char *getTo();
	char *getFrom();
	void setType(const char * const type);
	void setId(const char * const id);
	void setTo(const char * const to);
	void setFrom(const char * const from);
    }
}

#endif /* __LIBSTROPHE_STROPHEPP_H__ */
