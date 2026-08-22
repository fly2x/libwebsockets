/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
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
 * QUIC-TLS glue for the openHiTLS backend, using the openHiTLS QUIC-TLS
 * push API (hitls_quic_tls.h, available when openHiTLS was built with
 * -DHITLS_TLS_FEATURE_QUIC_TLS=ON).
 *
 * The openHiTLS QUIC-TLS API is BoringSSL-shaped: we register read/write
 * traffic-secret, add-handshake-data, flush-flight and send-alert callbacks
 * on the HITLS_Ctx, feed reassembled CRYPTO stream bytes in with
 * HITLS_QUIC_TLS_ProvideData() and drive the handshake with HITLS_Connect()/
 * HITLS_Accept().  No BSL_UIO is used for QUIC I/O.
 */

#include "private-lib-core.h"

void
lws_openhitls_quic_bio_free(struct lws *wsi);

#if defined(LWS_ROLE_QUIC) && defined(LWS_WITH_TLS) && defined(LWS_WITH_OPENHITLS)

#if defined(LWS_HAVE_HITLS_QUIC_TLS)

#include <hitls_quic_tls.h>

/*
 * Per-connection QUIC-TLS state, stashed in wsi->tls.client_bio.
 *
 * HITLS_QUIC_TLS_ProvideData() only accepts bytes for the level currently
 * reported by HITLS_QUIC_TLS_GetReadLevel(), so we keep per-level staging
 * buffers of in-order CRYPTO bytes the QUIC role has handed us but the TLS
 * stack has not accepted yet, and drain them as the read level advances.
 *
 * out/out_max/out_len are only used by the API self-test: when out is
 * non-NULL, handshake output is captured there as [level][len16] framed
 * chunks instead of being pushed to the QUIC role.
 */
struct lws_openhitls_quic {
	uint8_t			*rx[4];
	size_t			rx_len[4];

	uint8_t			*out;
	size_t			out_max;
	size_t			out_len;

	uint8_t			is_client;
	uint8_t			hs_done;
};

static struct lws_openhitls_quic *
lws_openhitls_quic_state(struct lws *wsi)
{
	return (struct lws_openhitls_quic *)wsi->tls.client_bio;
}

/*
 * RFC 9001: the QUIC packet-protection AEAD and header-protection ciphers
 * are fixed by the negotiated TLS 1.3 cipher suite, not by the secret length
 * (AES-128-GCM and ChaCha20-Poly1305 both use a 32-byte SHA-256 secret).
 * Report the negotiated suite so the QUIC role selects the matching AEAD.
 */
static void
lws_openhitls_quic_report_aead(struct lws *wsi, const HITLS_Cipher *cipher)
{
	uint16_t id;

	if (!cipher || HITLS_CFG_GetCipherSuite(cipher, &id) != HITLS_SUCCESS)
		return;

	switch (id) {
	case 0x1301: /* TLS_AES_128_GCM_SHA256 */
		wsi->tls.quic_aead = LWS_TLS_QUIC_AEAD_AES_128_GCM;
		break;
	case 0x1302: /* TLS_AES_256_GCM_SHA384 */
		wsi->tls.quic_aead = LWS_TLS_QUIC_AEAD_AES_256_GCM;
		break;
	case 0x1303: /* TLS_CHACHA20_POLY1305_SHA256 */
		wsi->tls.quic_aead = LWS_TLS_QUIC_AEAD_CHACHA20_POLY1305;
		break;
	default:
		/* leave any previously-reported suite in force */
		break;
	}
}

static int32_t
lws_openhitls_quic_secret(HITLS_Ctx *ctx, HITLS_QUIC_TLS_EncryptionLevel level,
			  const HITLS_Cipher *cipher, const uint8_t *secret,
			  size_t secret_len, int is_read)
{
	struct lws *wsi = (struct lws *)HITLS_GetUserData(ctx);
	struct lws_openhitls_quic *b;
	enum lws_tls_quic_secret_type t;
	int is_client;

	if (!wsi || !secret || secret_len > 48)
		return HITLS_SUCCESS;

	b = lws_openhitls_quic_state(wsi);
	is_client = b ? !!b->is_client : !!lwsi_role_client(wsi);

	lws_openhitls_quic_report_aead(wsi, cipher);

	switch (level) {
	case HITLS_QUIC_TLS_ENCRYPTION_LEVEL_EARLY_DATA:
		/* 0-RTT is not supported by the openHiTLS QUIC-TLS API yet,
		 * but map it correctly in case it appears */
		t = LWS_TLS_QUIC_SECRET_CLIENT_EARLY;
		break;
	case HITLS_QUIC_TLS_ENCRYPTION_LEVEL_HANDSHAKE:
		if (is_read)
			t = is_client ? LWS_TLS_QUIC_SECRET_SERVER_HANDSHAKE :
					LWS_TLS_QUIC_SECRET_CLIENT_HANDSHAKE;
		else
			t = is_client ? LWS_TLS_QUIC_SECRET_CLIENT_HANDSHAKE :
					LWS_TLS_QUIC_SECRET_SERVER_HANDSHAKE;
		break;
	case HITLS_QUIC_TLS_ENCRYPTION_LEVEL_APPLICATION:
		if (is_read)
			t = is_client ? LWS_TLS_QUIC_SECRET_SERVER_APPLICATION :
					LWS_TLS_QUIC_SECRET_CLIENT_APPLICATION;
		else
			t = is_client ? LWS_TLS_QUIC_SECRET_CLIENT_APPLICATION :
					LWS_TLS_QUIC_SECRET_SERVER_APPLICATION;
		break;
	default:
		/* INITIAL keys are derived by the QUIC role itself */
		return HITLS_SUCCESS;
	}

	if (wsi->tls.quic_secret_cb &&
	    wsi->tls.quic_secret_cb(wsi, t, secret, secret_len)) {
		lwsl_wsi_err(wsi, "quic_secret_cb failed for type %d", (int)t);
		return HITLS_REC_CB_FAIL;
	}

	return HITLS_SUCCESS;
}

static int32_t
lws_openhitls_quic_set_read_secret(HITLS_Ctx *ctx,
				   HITLS_QUIC_TLS_EncryptionLevel level,
				   const HITLS_Cipher *cipher,
				   const uint8_t *secret, size_t secret_len,
				   void *arg)
{
	(void)arg;
	return lws_openhitls_quic_secret(ctx, level, cipher, secret,
					 secret_len, 1);
}

static int32_t
lws_openhitls_quic_set_write_secret(HITLS_Ctx *ctx,
				    HITLS_QUIC_TLS_EncryptionLevel level,
				    const HITLS_Cipher *cipher,
				    const uint8_t *secret, size_t secret_len,
				    void *arg)
{
	(void)arg;
	return lws_openhitls_quic_secret(ctx, level, cipher, secret,
					 secret_len, 0);
}

static int32_t
lws_openhitls_quic_add_handshake_data(HITLS_Ctx *ctx,
				      HITLS_QUIC_TLS_EncryptionLevel level,
				      const uint8_t *data, size_t data_len,
				      void *arg)
{
	struct lws *wsi = (struct lws *)HITLS_GetUserData(ctx);
	struct lws_openhitls_quic *b;
	int lws_level = (int)level;

	(void)arg;

	if (!wsi || lws_level < 0 || lws_level > 3)
		return HITLS_REC_CB_FAIL;

	b = lws_openhitls_quic_state(wsi);

	if (b && b->out) {
		/* API self-test capture: [level][len16] framing */
		if (b->out_len + 3 + data_len > b->out_max) {
			lwsl_wsi_err(wsi, "quic api test out buffer overflow");
			return HITLS_REC_CB_FAIL;
		}
		b->out[b->out_len] = (uint8_t)lws_level;
		b->out[b->out_len + 1] = (uint8_t)((data_len >> 8) & 0xff);
		b->out[b->out_len + 2] = (uint8_t)(data_len & 0xff);
		memcpy(b->out + b->out_len + 3, data, data_len);
		b->out_len += 3 + data_len;

		return HITLS_SUCCESS;
	}

	if (wsi->quic.qn)
		lws_tls_quic_tx_crypto_cb(wsi, lws_level, data, data_len);

	return HITLS_SUCCESS;
}

static int32_t
lws_openhitls_quic_flush_flight(HITLS_Ctx *ctx, void *arg)
{
	(void)ctx;
	(void)arg;
	return HITLS_SUCCESS;
}

static int32_t
lws_openhitls_quic_send_alert(HITLS_Ctx *ctx,
			      HITLS_QUIC_TLS_EncryptionLevel level,
			      uint8_t alert, void *arg)
{
	struct lws *wsi = (struct lws *)HITLS_GetUserData(ctx);

	(void)level;
	(void)arg;

	if (wsi)
		wsi->tls.quic_alert = alert;

	return HITLS_SUCCESS;
}

static const HITLS_QUIC_TLS_Callbacks lws_openhitls_quic_cbs[] = {
	{ HITLS_QUIC_TLS_FUNC_SET_READ_SECRET,
	  (void *)lws_openhitls_quic_set_read_secret },
	{ HITLS_QUIC_TLS_FUNC_SET_WRITE_SECRET,
	  (void *)lws_openhitls_quic_set_write_secret },
	{ HITLS_QUIC_TLS_FUNC_ADD_HANDSHAKE_DATA,
	  (void *)lws_openhitls_quic_add_handshake_data },
	{ HITLS_QUIC_TLS_FUNC_FLUSH_FLIGHT,
	  (void *)lws_openhitls_quic_flush_flight },
	{ HITLS_QUIC_TLS_FUNC_SEND_ALERT,
	  (void *)lws_openhitls_quic_send_alert },
	HITLS_QUIC_TLS_CALLBACKS_END
};

int
lws_tls_quic_vhost_init(lws_tls_ctx *ctx)
{
	/*
	 * openHiTLS handles the quic_transport_parameters extension natively,
	 * nothing to register at the config level
	 */
	(void)ctx;
	return 0;
}

int
lws_tls_quic_init(struct lws *wsi, lws_tls_quic_secret_cb cb)
{
	struct lws_openhitls_quic *b;
	int32_t ret;

	if (!wsi->tls.ssl)
		return -1;

	wsi->tls.quic_secret_cb = cb;
	HITLS_SetUserData(wsi->tls.ssl, wsi);

	ret = HITLS_QUIC_TLS_SetQuicTlsMethod(wsi->tls.ssl,
					      lws_openhitls_quic_cbs, NULL);
	if (ret != HITLS_SUCCESS) {
		lwsl_wsi_err(wsi, "HITLS_QUIC_TLS_SetQuicTlsMethod: 0x%x",
			     (unsigned int)ret);
		return -1;
	}

	b = lws_zalloc(sizeof(*b), "openhitls quic");
	if (!b)
		return -1;

	b->is_client = lwsi_role_client(wsi) ? 1 : 0;
	wsi->tls.client_bio = (lws_tls_bio *)b;

	/*
	 * openHiTLS requires the local transport parameters to be installed
	 * before the handshake emits them (client: before the first
	 * HITLS_Connect; server: before EncryptedExtensions).  Apply any
	 * value the QUIC role stored before the TLS object existed, else a
	 * minimal placeholder so the mandatory extension is present (the
	 * QUIC role normally replaces it via
	 * lws_tls_quic_set_transport_parameters() before the handshake
	 * advances).
	 */
	if (wsi->tls.quic_tp_send && wsi->tls.quic_tp_send_len) {
		ret = HITLS_QUIC_TLS_SetTransportParams(wsi->tls.ssl,
						wsi->tls.quic_tp_send,
						wsi->tls.quic_tp_send_len);
		if (ret != HITLS_SUCCESS) {
			lwsl_wsi_err(wsi,
				     "HITLS_QUIC_TLS_SetTransportParams: 0x%x",
				     (unsigned int)ret);
			return -1;
		}
	} else {
		/* valid minimal TP: initial_max_data (0x04), 1-byte varint 0 */
		static const uint8_t dummy_tp[] = { 0x04, 0x01, 0x00 };

		(void)HITLS_QUIC_TLS_SetTransportParams(wsi->tls.ssl, dummy_tp,
							sizeof(dummy_tp));
	}

	return 0;
}

/*
 * The lws QUIC role maps a failed handshake to
 * CRYPTO_ERROR(wsi->tls.quic_alert), populated by the send-alert callback.
 * HITLS_QUIC_TLS_PROTOCOL_VIOLATION is authoritative and overrides any
 * reported alert: RFC 9001 requires closing with transport error
 * PROTOCOL_VIOLATION (0x0a), so enter the closing state directly here;
 * lws_quic_enter_closing_state() is first-call-wins, making the role's
 * later CRYPTO_ERROR close a no-op.
 */
static void
lws_openhitls_quic_fatal(struct lws *wsi, int32_t ret)
{
	if (ret == HITLS_QUIC_TLS_PROTOCOL_VIOLATION && wsi->quic.qn)
		lws_quic_enter_closing_state(wsi,
					     LWS_QUIC_ERR_PROTOCOL_VIOLATION,
					     0, 0);
}

int
lws_tls_quic_advance_handshake(struct lws *wsi, int level,
			       const uint8_t *in, size_t in_len,
			       uint8_t *out, size_t *out_len)
{
	struct lws_openhitls_quic *b = lws_openhitls_quic_state(wsi);
	HITLS_Ctx *ssl = wsi->tls.ssl;
	int rounds = 0, fatal = 0, progressed;
	int32_t ret;

	if (!b || !ssl)
		return -1;

	if (level < 0 || level > 3)
		return -1;

	if (in && in_len) {
		uint8_t *p = lws_realloc(b->rx[level], b->rx_len[level] + in_len,
					 "quic rx");

		if (!p)
			return -1;
		b->rx[level] = p;
		memcpy(b->rx[level] + b->rx_len[level], in, in_len);
		b->rx_len[level] += in_len;
	}

	b->out = out;
	b->out_max = (out && out_len) ? *out_len : 0;
	b->out_len = 0;

	do {
		HITLS_QUIC_TLS_EncryptionLevel cur;
		size_t chunk, cap;
		uint8_t done = 0;

		progressed = 0;

		/*
		 * Feed staged CRYPTO bytes for the level openHiTLS is
		 * currently reading at; bytes for later levels stay staged
		 * until the read level advances.
		 */
		cur = HITLS_QUIC_TLS_GetReadLevel(ssl);
		if ((int)cur >= 0 && (int)cur <= 3 && b->rx_len[cur]) {
			chunk = b->rx_len[cur];
			cap = HITLS_QUIC_TLS_GetMaxHandshakeFlightLen(ssl, cur);
			if (cap && chunk > cap)
				chunk = cap;

			ret = HITLS_QUIC_TLS_ProvideData(ssl, cur, b->rx[cur],
							 chunk);
			if (ret == HITLS_SUCCESS) {
				if (b->rx_len[cur] > chunk)
					memmove(b->rx[cur], b->rx[cur] + chunk,
						b->rx_len[cur] - chunk);
				b->rx_len[cur] -= chunk;
				progressed = 1;
			} else if (ret != HITLS_REC_RECORD_OVERFLOW) {
				lwsl_wsi_err(wsi,
					     "HITLS_QUIC_TLS_ProvideData: 0x%x",
					     (unsigned int)ret);
				fatal = 1;
				break;
			}
			/*
			 * on HITLS_REC_RECORD_OVERFLOW the level buffer is
			 * full: drive the handshake below so it drains, and
			 * retry on a later pass
			 */
		}

		if (!b->hs_done) {
			ret = b->is_client ? HITLS_Connect(ssl) :
					     HITLS_Accept(ssl);

			if (ret == HITLS_SUCCESS) {
				if (HITLS_IsHandShakeDone(ssl, &done) ==
							HITLS_SUCCESS && done) {
					b->hs_done = 1;
					progressed = 1;
					continue; /* drain any post-hs bytes */
				}
				progressed = 1;
			} else if (ret != HITLS_REC_NORMAL_RECV_BUF_EMPTY &&
				   ret != HITLS_REC_NORMAL_IO_BUSY) {
				lwsl_wsi_err(wsi, "HITLS %s failed: 0x%x",
					     b->is_client ? "Connect" : "Accept",
					     (unsigned int)ret);
				lws_openhitls_quic_fatal(wsi, ret);
				fatal = 1;
				break;
			}
		} else {
			if (!progressed)
				break;
			/*
			 * post-handshake CRYPTO data at the APPLICATION
			 * level, eg, NewSessionTicket
			 */
			ret = HITLS_QUIC_TLS_ProcessPostHandshake(ssl);
			if (ret == HITLS_SUCCESS ||
			    ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY) {
				/*
				 * A message larger than one ProvideData
				 * chunk (eg, a big NewSessionTicket) can
				 * still have bytes staged locally: feed
				 * those before concluding, else they would
				 * wait forever for peer data that never
				 * comes.  Only when the staging buffer is
				 * empty are we really done (all consumed,
				 * or fragmented and waiting for the peer).
				 */
				if (!b->rx_len[
				     HITLS_QUIC_TLS_ENCRYPTION_LEVEL_APPLICATION])
					break;
				continue;
			}

			lwsl_wsi_err(wsi,
				     "HITLS_QUIC_TLS_ProcessPostHandshake: 0x%x",
				     (unsigned int)ret);
			lws_openhitls_quic_fatal(wsi, ret);
			fatal = 1;
			break;
		}
	} while (progressed && ++rounds < 64);

	if (out_len)
		*out_len = b->out_len;
	b->out = NULL;
	b->out_max = 0;

	if (fatal)
		return -1;

	return b->hs_done ? 0 : 1;
}

int
lws_tls_quic_set_transport_parameters(struct lws *wsi, const uint8_t *tp,
				      size_t tp_len)
{
	uint8_t *p;

	if (!tp || !tp_len)
		return -1;

	if (wsi->tls.quic_tp_send) {
		lws_free((void *)wsi->tls.quic_tp_send);
		wsi->tls.quic_tp_send = NULL;
		wsi->tls.quic_tp_send_len = 0;
	}

	p = lws_malloc(tp_len, "quic tp send");
	if (!p)
		return -1;

	memcpy(p, tp, tp_len);
	wsi->tls.quic_tp_send = p;
	wsi->tls.quic_tp_send_len = tp_len;

	/* if QUIC-TLS is already set up on the connection, apply it now */
	if (wsi->tls.ssl && lws_openhitls_quic_state(wsi) &&
	    HITLS_QUIC_TLS_SetTransportParams(wsi->tls.ssl, p, tp_len) !=
								HITLS_SUCCESS)
		return -1;

	return 0;
}

int
lws_tls_quic_get_transport_parameters(struct lws *wsi, const uint8_t **tp,
				      size_t *tp_len)
{
	const uint8_t *peer = NULL;
	size_t peer_len = 0;
	uint8_t *p;

	if (wsi->tls.quic_tp_recv) {
		*tp = wsi->tls.quic_tp_recv;
		*tp_len = wsi->tls.quic_tp_recv_len;
		return 0;
	}

	if (!wsi->tls.ssl || !lws_openhitls_quic_state(wsi))
		return -1;

	if (HITLS_QUIC_TLS_GetPeerTransportParams(wsi->tls.ssl, &peer,
						  &peer_len) != HITLS_SUCCESS ||
	    !peer || !peer_len)
		return -1;

	/*
	 * the openHiTLS pointer is borrowed (valid until HITLS_Clear/Free);
	 * take a copy so the usual wsi->tls.quic_tp_recv lifetime rules apply
	 */
	p = lws_malloc(peer_len, "quic_tp_recv");
	if (!p)
		return -1;

	memcpy(p, peer, peer_len);
	wsi->tls.quic_tp_recv = p;
	wsi->tls.quic_tp_recv_len = peer_len;

	*tp = wsi->tls.quic_tp_recv;
	*tp_len = wsi->tls.quic_tp_recv_len;

	return 0;
}

int
lws_tls_quic_migrate_wsi(struct lws *old_wsi, struct lws *new_wsi)
{
	(void)old_wsi;

	if (!new_wsi || !new_wsi->tls.ssl)
		return -1;

	/* re-point the HITLS_Ctx user data at the new owning wsi */
	HITLS_SetUserData(new_wsi->tls.ssl, new_wsi);

	return 0;
}

/*
 * API self-test: run a complete in-memory QUIC-TLS handshake between two
 * bare wsis through the glue above, and check traffic secrets were derived
 * and transport parameters exchanged both ways.
 */

static int test_secrets_extracted;

static int
test_secret_cb(struct lws *wsi, enum lws_tls_quic_secret_type type,
	       const uint8_t *secret, size_t secret_len)
{
	(void)wsi;
	(void)secret;
	lwsl_notice("%s: extracted type %d, len %d\n", __func__, (int)type,
		    (int)secret_len);
	test_secrets_extracted++;
	return 0;
}

static const uint8_t test_alpn[] = { 4, 't', 'e', 's', 't' };

static int32_t
test_alpn_select_cb(HITLS_Ctx *ctx, uint8_t **selected_proto,
		    uint8_t *selected_proto_size, uint8_t *client_alpn_list,
		    uint32_t client_alpn_list_size, void *user_data)
{
	(void)ctx;
	(void)client_alpn_list;
	(void)client_alpn_list_size;
	(void)user_data;

	*selected_proto = (uint8_t *)&test_alpn[1];
	*selected_proto_size = test_alpn[0];

	return HITLS_ALPN_ERR_OK;
}

/* self-signed ECDSA P-256 test cert, CN=lws-quic-api-test, notAfter 2126 */
static const char test_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIBjzCCATWgAwIBAgIUFnrOYa+GUinx61ymOPnPb5Y910swCgYIKoZIzj0EAwIw\n"
	"HDEaMBgGA1UEAwwRbHdzLXF1aWMtYXBpLXRlc3QwIBcNMjYwODIyMDY0MjA1WhgP\n"
	"MjEyNjA3MjkwNjQyMDVaMBwxGjAYBgNVBAMMEWx3cy1xdWljLWFwaS10ZXN0MFkw\n"
	"EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEusQZCu993CN7lXhX5OYfaf8HNNe8DQsI\n"
	"gL42KF3S65MQ6DqxcENNJOp5vDIehgvqrSpqq72os6VxRDaOQRzPrKNTMFEwHQYD\n"
	"VR0OBBYEFNn9xtsniXFaejZADCv4cs7nzlfyMB8GA1UdIwQYMBaAFNn9xtsniXFa\n"
	"ejZADCv4cs7nzlfyMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIg\n"
	"ZWIHsx90mvbwotSPXxOB6rlLZe3WR3NUY7sE6K+WZH0CIQCKdpv9IvLeORWMlzgV\n"
	"iyVxxeu/GAOQ/nWljO9W5olZXQ==\n"
	"-----END CERTIFICATE-----\n";

static const char test_key_pem[] =
	"-----BEGIN PRIVATE KEY-----\n"
	"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgdNQXHUXgbOrbnfTs\n"
	"1f9qVtalFdaAzZUOOHJWKs/5fMahRANCAAS6xBkK733cI3uVeFfk5h9p/wc017wN\n"
	"CwiAvjYoXdLrkxDoOrFwQ00k6nm8Mh6GC+qtKmqrvaizpXFENo5BHM+s\n"
	"-----END PRIVATE KEY-----\n";

/*
 * Feed [level][len16]-framed handshake chunks from one side into the peer,
 * collecting the peer's framed output into out
 */
static int
test_pump(struct lws *dest, const uint8_t *frames, size_t frames_len,
	  uint8_t *out, size_t out_cap, size_t *out_used)
{
	size_t pos = 0;

	while (pos + 3 <= frames_len) {
		int lvl = frames[pos];
		size_t plen = ((size_t)frames[pos + 1] << 8) | frames[pos + 2];
		size_t space = out_cap - *out_used;

		if (pos + 3 + plen > frames_len) {
			lwsl_err("%s: truncated frame\n", __func__);
			return -1;
		}

		if (lws_tls_quic_advance_handshake(dest, lvl, frames + pos + 3,
						   plen, out + *out_used,
						   &space) < 0)
			return -1;

		*out_used += space;
		pos += 3 + plen;
	}

	return 0;
}

int
lws_tls_quic_api_test(void)
{
	struct lws wsi_client, wsi_server;
	HITLS_Config *cconf = NULL, *sconf = NULL;
	uint8_t *c2s = NULL, *s2c = NULL;
	size_t c2s_len = 0, s2c_len = 0;
	const size_t bufsz = 16384;
	int iter = 0, ret = -1;

	const uint8_t *recvd;
	size_t recvd_len;
	uint8_t ctp[] = { 0x01, 0x02, 0x03, 0x04 };
	uint8_t stp[] = { 0x05, 0x06, 0x07, 0x08 };

	memset(&wsi_client, 0, sizeof(wsi_client));
	wsi_client.wsistate = LWSIFR_CLIENT;
	memset(&wsi_server, 0, sizeof(wsi_server));
	wsi_server.wsistate = LWSIFR_SERVER;

	test_secrets_extracted = 0;

	/*
	 * the API test runs without an lws_context, so perform the library
	 * init that lws_context_init_ssl_library() would normally do; both
	 * calls are idempotent
	 */
	if (BSL_ERR_Init() != BSL_SUCCESS ||
	    CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL) != CRYPT_SUCCESS) {
		lwsl_err("%s: openHiTLS library init failed\n", __func__);
		goto bail;
	}

	c2s = lws_malloc(bufsz, "qt c2s");
	s2c = lws_malloc(bufsz, "qt s2c");
	if (!c2s || !s2c)
		goto bail;

	cconf = HITLS_CFG_NewTLS13Config();
	sconf = HITLS_CFG_NewTLS13Config();
	if (!cconf || !sconf) {
		lwsl_err("%s: HITLS_CFG_NewTLS13Config failed\n", __func__);
		goto bail;
	}

	if (HITLS_CFG_SetVerifyNoneSupport(cconf, true) != HITLS_SUCCESS) {
		lwsl_err("%s: SetVerifyNoneSupport failed\n", __func__);
		goto bail;
	}

	if (HITLS_CFG_SetAlpnProtosSelectCb(sconf, test_alpn_select_cb,
					    NULL) != HITLS_SUCCESS) {
		lwsl_err("%s: SetAlpnProtosSelectCb failed\n", __func__);
		goto bail;
	}

	if (HITLS_CFG_LoadCertBuffer(sconf, (const uint8_t *)test_cert_pem,
				     sizeof(test_cert_pem) - 1,
				     TLS_PARSE_FORMAT_PEM) != HITLS_SUCCESS) {
		lwsl_err("%s: server cert load failed\n", __func__);
		goto bail;
	}
	if (HITLS_CFG_LoadKeyBuffer(sconf, (const uint8_t *)test_key_pem,
				    sizeof(test_key_pem) - 1,
				    TLS_PARSE_FORMAT_PEM) != HITLS_SUCCESS) {
		lwsl_err("%s: server key load failed\n", __func__);
		goto bail;
	}
	if (HITLS_CFG_CheckPrivateKey(sconf) != HITLS_SUCCESS) {
		lwsl_err("%s: server cert/key mismatch\n", __func__);
		goto bail;
	}

	wsi_client.tls.ssl = HITLS_New(cconf);
	wsi_server.tls.ssl = HITLS_New(sconf);
	if (!wsi_client.tls.ssl || !wsi_server.tls.ssl) {
		lwsl_err("%s: HITLS_New failed\n", __func__);
		goto bail;
	}

	if (HITLS_SetAlpnProtos(wsi_client.tls.ssl, (uint8_t *)test_alpn,
				sizeof(test_alpn)) != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_SetAlpnProtos failed\n", __func__);
		goto bail;
	}

	if (lws_tls_quic_init(&wsi_client, test_secret_cb) ||
	    lws_tls_quic_init(&wsi_server, test_secret_cb)) {
		lwsl_err("%s: lws_tls_quic_init failed\n", __func__);
		goto bail;
	}

	if (lws_tls_quic_set_transport_parameters(&wsi_client, ctp,
						  sizeof(ctp)) ||
	    lws_tls_quic_set_transport_parameters(&wsi_server, stp,
						  sizeof(stp))) {
		lwsl_err("%s: set_transport_parameters failed\n", __func__);
		goto bail;
	}

	/* start the handshake by advancing the client with no input */
	c2s_len = bufsz;
	if (lws_tls_quic_advance_handshake(&wsi_client, 0, NULL, 0, c2s,
					   &c2s_len) < 0) {
		lwsl_err("%s: initial client advance failed\n", __func__);
		goto bail;
	}

	while (iter++ < 10) {
		struct lws_openhitls_quic *bc, *bs;

		if (c2s_len) {
			lwsl_notice("C -> S: %d bytes\n", (int)c2s_len);
			s2c_len = 0;
			if (test_pump(&wsi_server, c2s, c2s_len, s2c, bufsz,
				      &s2c_len))
				goto bail;
			c2s_len = 0;
		}

		if (s2c_len) {
			lwsl_notice("S -> C: %d bytes\n", (int)s2c_len);
			c2s_len = 0;
			if (test_pump(&wsi_client, s2c, s2c_len, c2s, bufsz,
				      &c2s_len))
				goto bail;
			s2c_len = 0;
		}

		bc = lws_openhitls_quic_state(&wsi_client);
		bs = lws_openhitls_quic_state(&wsi_server);
		if (bc && bs && bc->hs_done && bs->hs_done && !c2s_len &&
		    !s2c_len)
			break;
	}

	{
		struct lws_openhitls_quic *bc =
					lws_openhitls_quic_state(&wsi_client);

		if (!bc || !bc->hs_done) {
			lwsl_err("%s: handshake did not complete\n", __func__);
			goto bail;
		}
	}

	lwsl_notice("Handshake finished, secrets extracted: %d\n",
		    test_secrets_extracted);

	/* client hs + server hs + client app + server app, both sides */
	if (test_secrets_extracted < 8) {
		lwsl_err("%s: too few secrets extracted (%d)\n", __func__,
			 test_secrets_extracted);
		goto bail;
	}

	if (lws_tls_quic_get_transport_parameters(&wsi_client, &recvd,
						  &recvd_len) ||
	    recvd_len != sizeof(stp) || memcmp(recvd, stp, sizeof(stp))) {
		lwsl_err("Client failed to receive Server TP\n");
		goto bail;
	}

	if (lws_tls_quic_get_transport_parameters(&wsi_server, &recvd,
						  &recvd_len) ||
	    recvd_len != sizeof(ctp) || memcmp(recvd, ctp, sizeof(ctp))) {
		lwsl_err("Server failed to receive Client TP\n");
		goto bail;
	}

	lwsl_notice("Transport parameters successfully exchanged\n");

	ret = 0;

bail:
	lws_openhitls_quic_bio_free(&wsi_client);
	lws_openhitls_quic_bio_free(&wsi_server);
	if (wsi_client.tls.ssl)
		HITLS_Free(wsi_client.tls.ssl);
	if (wsi_server.tls.ssl)
		HITLS_Free(wsi_server.tls.ssl);
	if (cconf)
		HITLS_CFG_FreeConfig(cconf);
	if (sconf)
		HITLS_CFG_FreeConfig(sconf);
	lws_free(c2s);
	lws_free(s2c);

	return ret;
}

#else /* !LWS_HAVE_HITLS_QUIC_TLS */

int
lws_tls_quic_vhost_init(lws_tls_ctx *ctx)
{
	(void)ctx;
	return 0;
}

int
lws_tls_quic_init(struct lws *wsi, lws_tls_quic_secret_cb cb)
{
	(void)cb;
	lwsl_wsi_err(wsi, "openHiTLS was built without the QUIC-TLS API "
			  "(HITLS_TLS_FEATURE_QUIC_TLS)");
	return -1;
}

int
lws_tls_quic_advance_handshake(struct lws *wsi, int level,
			       const uint8_t *in, size_t in_len,
			       uint8_t *out, size_t *out_len)
{
	(void)wsi;
	(void)level;
	(void)in;
	(void)in_len;
	(void)out;
	(void)out_len;
	return -1;
}

int
lws_tls_quic_set_transport_parameters(struct lws *wsi, const uint8_t *tp,
				      size_t tp_len)
{
	(void)wsi;
	(void)tp;
	(void)tp_len;
	return -1;
}

int
lws_tls_quic_get_transport_parameters(struct lws *wsi, const uint8_t **tp,
				      size_t *tp_len)
{
	(void)wsi;
	(void)tp;
	(void)tp_len;
	return -1;
}

int
lws_tls_quic_api_test(void)
{
	return 0;
}

int
lws_tls_quic_migrate_wsi(struct lws *old_wsi, struct lws *new_wsi)
{
	(void)old_wsi;
	(void)new_wsi;
	return -1;
}

#endif /* LWS_HAVE_HITLS_QUIC_TLS */

void
lws_openhitls_quic_bio_free(struct lws *wsi)
{
#if defined(LWS_HAVE_HITLS_QUIC_TLS)
	struct lws_openhitls_quic *b;
	int n;
#endif

	if (!wsi)
		return;

#if defined(LWS_HAVE_HITLS_QUIC_TLS)
	b = lws_openhitls_quic_state(wsi);
	if (b) {
		for (n = 0; n < 4; n++)
			if (b->rx[n])
				lws_free(b->rx[n]);
		lws_free(b);
		wsi->tls.client_bio = NULL;
	}
#endif

	if (wsi->tls.quic_tp_recv) {
		lws_free((void *)wsi->tls.quic_tp_recv);
		wsi->tls.quic_tp_recv = NULL;
		wsi->tls.quic_tp_recv_len = 0;
	}

	if (wsi->tls.quic_tp_send) {
		lws_free((void *)wsi->tls.quic_tp_send);
		wsi->tls.quic_tp_send = NULL;
		wsi->tls.quic_tp_send_len = 0;
	}
}

#endif /* LWS_ROLE_QUIC && LWS_WITH_TLS && LWS_WITH_OPENHITLS */
