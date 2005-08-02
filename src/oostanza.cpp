#include "strophe.h"
#include "strophepp.h"

using namespace XMPP;

void *Stanza::operator new(size_t size, Context *ctx)
{
    return ctx->alloc(size);
}

void Stanza::operator delete(void *p, Context *ctx)
{
    ctx->free(p);
}

Stanza::Stanza(Context *ctx)
{
    m_ctx = ctx;
    m_stanza = ::xmpp_stanza_new(ctx->getContext());
    // TODO: check for errors
}

Stanza::~Stanza()
{
    ::xmpp_stanza_release(m_stanza);
}

void Stanza::release()
{
    if (::xmpp_stanza_release(m_stanza))
	delete(m_ctx) this;
}

Stanza *Stanza::clone()
{
    ::xmpp_stanza_clone(m_stanza);
    return this;
}

Stanza *Stanza::copy()
{
    // TODO
    return NULL;
}


