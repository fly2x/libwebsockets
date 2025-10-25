/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2025 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * openHiTLS SSL/TLS operations and I/O
 */

#include "private-lib-core.h"
#include "private-lib-tls-openhitls.h"

#include <hitls/bsl/bsl_errno.h>
#include <errno.h>
#include <sys/socket.h>

/*
 * UIO read callback - UNUSED (we use BSL_UIO_TcpMethod() instead)
 * Kept for reference in case custom UIO is needed in the future
 */
#if 0
static int32_t
lws_uio_read_cb(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen)
{
	struct lws *wsi = (struct lws *)BSL_UIO_GetCtx(uio);
	ssize_t n;

	if (!wsi || !buf || !readLen) {
		lwsl_err("%s: invalid parameters\n", __func__);
		return HITLS_NULL_INPUT;
	}

	n = recv(wsi->desc.sockfd, buf, len, 0);

	if (n > 0) {
		*readLen = (uint32_t)n;
		lwsl_info("%s: read %d bytes from fd %d\n", __func__, (int)n, wsi->desc.sockfd);
		return BSL_SUCCESS;
	} else if (n == 0) {
		/* Connection closed - return EOF */
		*readLen = 0;
		lwsl_warn("%s: connection closed (EOF) on fd %d\n", __func__, wsi->desc.sockfd);
		return BSL_UIO_IO_EOF;
	} else {
		*readLen = 0;
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			/* Non-blocking socket, no data available - return success with readLen=0 */
			lwsl_info("%s: would block (no data) on fd %d\n", __func__, wsi->desc.sockfd);
			return BSL_SUCCESS;
		}
		lwsl_err("%s: recv error on fd %d: %s (errno=%d)\n", __func__, wsi->desc.sockfd, strerror(errno), errno);
		return BSL_UIO_IO_EXCEPTION;
	}
}

/*
 * UIO write callback - writes data to libwebsockets socket
 */
static int32_t
lws_uio_write_cb(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen)
{
	struct lws *wsi = (struct lws *)BSL_UIO_GetCtx(uio);
	ssize_t n;

	if (!wsi || !buf || !writeLen) {
		lwsl_err("%s: invalid parameters\n", __func__);
		return HITLS_NULL_INPUT;
	}

	n = send(wsi->desc.sockfd, buf, len, MSG_NOSIGNAL);

	if (n > 0) {
		*writeLen = (uint32_t)n;
		lwsl_info("%s: wrote %d bytes to fd %d\n", __func__, (int)n, wsi->desc.sockfd);
		return BSL_SUCCESS;
	} else if (n == 0) {
		/* Zero bytes written - return success with writeLen=0 */
		*writeLen = 0;
		lwsl_info("%s: wrote 0 bytes to fd %d\n", __func__, wsi->desc.sockfd);
		return BSL_SUCCESS;
	} else {
		*writeLen = 0;
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			/* Non-blocking socket, would block - return success with writeLen=0 */
			lwsl_info("%s: would block on write to fd %d\n", __func__, wsi->desc.sockfd);
			return BSL_SUCCESS;
		}
		lwsl_err("%s: send error on fd %d: %s (errno=%d)\n", __func__, wsi->desc.sockfd, strerror(errno), errno);
		return BSL_UIO_IO_EXCEPTION;
	}
}
#endif /* 0 - unused custom UIO callbacks */

/*
 * Setup UIO for openHiTLS context
 */
int
lws_openhitls_setup_uio(struct lws *wsi)
{
	BSL_UIO *uio;
	int32_t ret;
	int fd;

	if (!wsi->tls.ssl) {
		lwsl_err("%s: no SSL context\n", __func__);
		return -1;
	}

	/* Create UIO object using built-in TCP method */
	uio = BSL_UIO_New(BSL_UIO_TcpMethod());
	if (!uio) {
		lwsl_err("%s: BSL_UIO_New failed\n", __func__);
		return -1;
	}

	/* Set the socket file descriptor */
	fd = wsi->desc.sockfd;
	ret = BSL_UIO_Ctrl(uio, BSL_UIO_SET_FD, (int32_t)sizeof(fd), &fd);
	if (ret != HITLS_SUCCESS) {
		lwsl_err("%s: BSL_UIO_SET_FD failed: 0x%x (fd=%d)\n", __func__, ret, fd);
		BSL_UIO_Free(uio);
		return -1;
	}

	/* Bind UIO to HITLS_Ctx */
	ret = HITLS_SetUio((HITLS_Ctx *)wsi->tls.ssl, uio);
	if (ret != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_SetUio failed: 0x%x\n", __func__, ret);
		BSL_UIO_Free(uio);
		return -1;
	}

	/* Store UIO in client_bio field for later cleanup */
	wsi->tls.client_bio = (lws_tls_bio *)uio;

	lwsl_info("%s: UIO setup complete for wsi %p (fd=%d)\n", __func__, wsi, fd);

	return 0;
}

/*
 * Destroy UIO adapter
 */
void
lws_openhitls_destroy_uio(struct lws *wsi)
{
	BSL_UIO *uio;

	if (!wsi->tls.client_bio)
		return;

	uio = (BSL_UIO *)wsi->tls.client_bio;

	BSL_UIO_Free(uio);
	/* Note: method is managed internally by BSL_UIO */

	wsi->tls.client_bio = NULL;

	lwsl_info("%s: UIO destroyed for wsi %p\n", __func__, wsi);
}

/*
 * SSL read operation
 */
int
lws_ssl_capable_read(struct lws *wsi, unsigned char *buf, size_t len)
{
	uint32_t readLen = 0;
	int32_t ret;

	if (!wsi->tls.ssl) {
		lwsl_err("%s: no SSL context\n", __func__);
		return -1;
	}

	ret = HITLS_Read((HITLS_Ctx *)wsi->tls.ssl, buf, (uint32_t)len, &readLen);

	switch (ret) {
	case HITLS_SUCCESS:
		lwsl_debug("%s: read %u bytes\n", __func__, readLen);
		return (int)readLen;

	case HITLS_REC_NORMAL_RECV_BUF_EMPTY:
		lwsl_debug("%s: need more data\n", __func__);
		return LWS_SSL_CAPABLE_MORE_SERVICE;

	case HITLS_REC_NORMAL_IO_BUSY:
		lwsl_debug("%s: I/O busy\n", __func__);
		return LWS_SSL_CAPABLE_MORE_SERVICE;

	case HITLS_WANT_READ:
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;

	case HITLS_WANT_WRITE:
		return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;

	default:
		lwsl_err("%s: HITLS_Read failed: 0x%x\n", __func__, ret);
		lws_tls_err_describe_clear();
		return -1;
	}
}

/*
 * SSL write operation
 */
int
lws_ssl_capable_write(struct lws *wsi, unsigned char *buf, size_t len)
{
	uint32_t writeLen = 0;
	int32_t ret;

	if (!wsi->tls.ssl) {
		lwsl_err("%s: no SSL context\n", __func__);
		return -1;
	}

	ret = HITLS_Write((HITLS_Ctx *)wsi->tls.ssl, buf, (uint32_t)len, &writeLen);

	switch (ret) {
	case HITLS_SUCCESS:
		lwsl_debug("%s: wrote %u bytes\n", __func__, writeLen);
		return (int)writeLen;

	case HITLS_REC_NORMAL_IO_BUSY:
		lwsl_debug("%s: I/O busy\n", __func__);
		return LWS_SSL_CAPABLE_MORE_SERVICE;

	case HITLS_WANT_READ:
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;

	case HITLS_WANT_WRITE:
		return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;

	default:
		lwsl_err("%s: HITLS_Write failed: 0x%x\n", __func__, ret);
		lws_tls_err_describe_clear();
		return -1;
	}
}

/*
 * Check if there's pending SSL data in buffers
 */
int
lws_ssl_pending(struct lws *wsi)
{
	uint32_t pending;

	if (!wsi->tls.ssl)
		return 0;

	pending = HITLS_GetReadPendingBytes((HITLS_Ctx *)wsi->tls.ssl);

	lwsl_debug("%s: %u bytes pending\n", __func__, pending);

	return (int)pending;
}

/*
 * Close SSL connection
 */
int
lws_ssl_close(struct lws *wsi)
{
	if (!wsi->tls.ssl)
		return 0;

	lwsl_info("%s: closing SSL for wsi %p\n", __func__, wsi);

	/* Send close_notify */
	HITLS_Close((HITLS_Ctx *)wsi->tls.ssl);

	/* Destroy UIO */
	lws_openhitls_destroy_uio(wsi);

	/* Free HITLS_Ctx */
	HITLS_Free((HITLS_Ctx *)wsi->tls.ssl);
	wsi->tls.ssl = NULL;

	return 0;
}

/*
 * Shutdown SSL connection
 */
enum lws_ssl_capable_status
__lws_tls_shutdown(struct lws *wsi)
{
	int32_t ret;

	if (!wsi->tls.ssl)
		return LWS_SSL_CAPABLE_DONE;

	ret = HITLS_Close((HITLS_Ctx *)wsi->tls.ssl);

	switch (ret) {
	case HITLS_SUCCESS:
		lwsl_info("%s: shutdown complete\n", __func__);
		return LWS_SSL_CAPABLE_DONE;

	case HITLS_REC_NORMAL_IO_BUSY:
		lwsl_debug("%s: shutdown in progress\n", __func__);
		return LWS_SSL_CAPABLE_MORE_SERVICE;

	default:
		lwsl_err("%s: shutdown failed: %d\n", __func__, ret);
		return LWS_SSL_CAPABLE_ERROR;
	}
}

/*
 * Get SSL error
 */
int
lws_ssl_get_error(struct lws *wsi, int n)
{
	int32_t err;

	if (!wsi->tls.ssl)
		return -1;

	err = HITLS_GetErrorCode((HITLS_Ctx *)wsi->tls.ssl);

	/* Map openHiTLS errors to SSL error codes */
	switch (err) {
	case HITLS_REC_NORMAL_RECV_BUF_EMPTY:
		return SSL_ERROR_WANT_READ;
	case HITLS_REC_NORMAL_IO_BUSY:
		return SSL_ERROR_WANT_WRITE;
	case HITLS_SUCCESS:
		return SSL_ERROR_NONE;
	default:
		/* Store error code */
		lws_snprintf(wsi->tls.err_helper, sizeof(wsi->tls.err_helper),
			     "HITLS error: 0x%x", err);
		return SSL_ERROR_SSL;
	}
}

/*
 * Error handling
 */
void
lws_tls_err_describe_clear(void)
{
	/*
	 * openHiTLS doesn't maintain a global error queue like OpenSSL
	 * Errors are retrieved per-context using HITLS_GetErrorCode()
	 */
}

/*
 * Fake POLLIN for buffered data
 */
static int
tops_fake_POLLIN_for_buffered_openhitls(struct lws_context_per_thread *pt)
{
	return lws_tls_fake_POLLIN_for_buffered(pt);
}

/*
 * TLS operations table for openHiTLS
 */
const struct lws_tls_ops tls_ops_openhitls = {
	.fake_POLLIN_for_buffered = tops_fake_POLLIN_for_buffered_openhitls,
};

/*
 * BIO creation (not used by openHiTLS, but required by interface)
 */
int
lws_ssl_client_bio_create(struct lws *wsi)
{
	/* openHiTLS uses UIO instead of BIO, setup happens in lws_openhitls_setup_uio */
	return 0;
}
