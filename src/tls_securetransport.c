// Secure Transport implementation of TLS by Christopher A. Taylor (2013)

#include <Security/Security.h>
#include <Security/SecureTransport.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonDigest.h>

#include "common.h"
#include "tls.h"
#include "sock.h"

struct _tls {
    xmpp_ctx_t *ctx; /* do we need this? */
    sock_t sock;

	SSLContextRef sslctx;
};

void tls_initialize(void)
{
}

void tls_shutdown(void)
{
}

OSStatus MySSLReadFunction(SSLConnectionRef connection, void *data, size_t *dataLength) {
	size_t bytesToGo = *dataLength;
	size_t initLen = bytesToGo;
	UInt8 *currData = (UInt8 *)data;
	/*int sock = *(int *)connection;*/
	tls_t *connssl = (tls_t *)connection;
	int sock = connssl->sock;
	OSStatus rtn = noErr;
	size_t bytesRead;
	ssize_t rrtn;
	int theErr;

	*dataLength = 0;

	for(;;) {
		bytesRead = 0;
		rrtn = read(sock, currData, bytesToGo);
		if(rrtn <= 0) {
			/* this is guesswork... */
			theErr = errno;
			if(rrtn == 0) { /* EOF = server hung up */
				/* the framework will turn this into errSSLClosedNoNotify */
				rtn = errSSLClosedGraceful;
			}
			else /* do the switch */
				switch(theErr) {
					case ENOENT:
						/* connection closed */
						rtn = errSSLClosedGraceful;
						break;
					case ECONNRESET:
						rtn = errSSLClosedAbort;
						break;
					case EAGAIN:
						rtn = errSSLWouldBlock;
						//connssl->ssl_direction = false;
						break;
					default:
						rtn = errSSLClosedAbort;
						break;
				}
			break;
		}
		else {
			bytesRead = rrtn;
		}
		bytesToGo -= bytesRead;
		currData  += bytesRead;

		if(bytesToGo == 0) {
			/* filled buffer with incoming data, done */
			break;
		}
	}
	*dataLength = initLen - bytesToGo;

	return rtn;
}

OSStatus MySSLWriteFunction(SSLConnectionRef connection, const void *data, size_t *dataLength) {
	size_t bytesSent = 0;
	/*int sock = *(int *)connection;*/
	tls_t *connssl = (tls_t *)connection;
	int sock = connssl->sock;
	ssize_t length;
	size_t dataLen = *dataLength;
	const UInt8 *dataPtr = (UInt8 *)data;
	OSStatus ortn;
	int theErr;

	*dataLength = 0;

	do {
		length = write(sock,
				(char*)dataPtr + bytesSent,
				dataLen - bytesSent);
	} while((length > 0) &&
			( (bytesSent += length) < dataLen) );

	if(length <= 0) {
		theErr = errno;
		if(theErr == EAGAIN) {
			ortn = errSSLWouldBlock;
			//connssl->ssl_direction = true;
		}
		else {
			ortn = errSSLClosedAbort;
		}
	}
	else {
		ortn = noErr;
	}
	*dataLength = bytesSent;
	return ortn;
}

tls_t *tls_new(xmpp_ctx_t *ctx, sock_t sock)
{
	tls_t *tls = xmpp_alloc(ctx, sizeof(tls_t));

	if (tls) {
		tls->ctx = ctx;
		tls->sock = sock;
		tls->sslctx = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);

		SSLSetIOFuncs(tls->sslctx, MySSLReadFunction, MySSLWriteFunction);

		SSLSetConnection(tls->sslctx, tls);
	}

	return tls;
}

void tls_free(tls_t *tls)
{
	CFRelease(tls->sslctx);

    xmpp_free(tls->ctx, tls);
}

int tls_set_credentials(tls_t *tls, const char *cafilename)
{
/*	
	Not implemented in OpenSSL version so we should not need it either.
	But if we want to do it here's a place to start:

	FILE * ret = fopen(cafilename, options);
	void *data = malloc(bytes);
	fread(data, 1, bytes, ret); 
	fclose(ret);
	NSData *myCertData = [NSData dataWithBytesNoCopy:data length:bytes];  <- requires -ObjC compile option?

	SecCertificateRef cert = SecCertificateCreateWithData(kCFAllocatorDefault, myCertData); 
	CFArrayRef certRefs = CFArrayCreate(kCFAllocatorDefault, (const void **)&cert, 1, NULL); 

	SSLSetCertificate(tls->sslctx, certRefs);
*/
    return -1;
}

int tls_start(tls_t *tls)
{
    int ret;

    /* Since we're non-blocking, loop the connect call until it
       succeeds or fails */
	do {
		ret = SSLHandshake(tls->sslctx);
	} while (ret == errSSLWouldBlock);

	return ret < 0 ? -1 : 0;
}

int tls_stop(tls_t *tls)
{
	SSLClose(tls->sslctx);
	return 0;
}

int tls_is_recoverable(int error)
{
	switch (error) {
		case errSSLWouldBlock:
			return true;
		default:
			break;
	}

	return false;
}

int tls_error(tls_t *tls)
{
    /* todo: some kind of error polling/dump */
    return 0;
}

int tls_pending(tls_t *tls)
{
	size_t buffer;

	if (SSLGetBufferedReadSize(tls->sslctx, &buffer) < 0) {
		return 0;
	}

	return buffer;
}

int tls_read(tls_t *tls, void * const buff, const size_t len)
{
	size_t processed;

	SSLRead(tls->sslctx, buff, len, &processed);

	return processed;
}

int tls_write(tls_t *tls, const void * const buff, const size_t len)
{
	size_t processed;

	SSLWrite(tls->sslctx, buff, len, &processed);

	return processed;
}

int tls_clear_pending_write(tls_t *tls)
{
    return 0;
}

