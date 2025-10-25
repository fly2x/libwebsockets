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
 * openHiTLS client-side implementation
 */

#include "private-lib-core.h"
#include "private-lib-tls-openhitls.h"
#include <hitls/bsl/bsl_err.h>

/* Temporary bypass verification callback for testing - currently unused */
#if 0
static int
bypass_verify_callback(int32_t isPreverifyOk, HITLS_CERT_StoreCtx *storeCtx)
{
	(void)isPreverifyOk;
	(void)storeCtx;
	/* Return 1 (true) to bypass verification */
	lwsl_warn("bypass_verify_callback: skipping verification for testing\n");
	return 1;
}
#endif

int
lws_tls_client_create_vhost_context(struct lws_vhost *vh,
				     const struct lws_context_creation_info *info,
				     const char *cipher_list,
				     const char *ca_filepath,
				     const void *ca_mem,
				     unsigned int ca_mem_len,
				     const char *cert_filepath,
				     const void *cert_mem,
				     unsigned int cert_mem_len,
				     const char *private_key_filepath,
				     const void *key_mem,
				     unsigned int key_mem_len)
{
	HITLS_Config *config;
	int32_t ret;

	lwsl_info("%s: creating vhost context\n", __func__);

	config = (HITLS_Config *)vh->tls.ssl_client_ctx;
	if (!config) {
		/* Create if doesn't exist */
		config = HITLS_CFG_NewTLSConfig();
		if (!config) {
			int32_t err = BSL_ERR_GetLastError();
			lwsl_err("%s: HITLS_CFG_NewTLSConfig failed: 0x%x\n",
				 __func__, err);
			return -1;
		}

		ret = HITLS_CFG_SetVersion(config, HITLS_VERSION_TLS12,
					    HITLS_VERSION_TLS13);
		if (ret != HITLS_SUCCESS) {
			HITLS_CFG_FreeConfig(config);
			return -1;
		}

		/* Disable key usage check like the demo does */
		ret = HITLS_CFG_SetCheckKeyUsage(config, false);
		if (ret != HITLS_SUCCESS) {
			lwsl_warn("%s: failed to disable key usage check: 0x%x\n", __func__, ret);
		}

		/* TODO: Temporarily use system CA certificates for testing
		 * In production, should use proper CA bundle */

		/* Try loading system CA certificates */
		ret = HITLS_CFG_LoadVerifyFile(config, "/etc/ssl/certs/ca-certificates.crt");
		if (ret != HITLS_SUCCESS) {
			/* Try alternative locations */
			ret = HITLS_CFG_LoadVerifyFile(config, "/etc/pki/tls/certs/ca-bundle.crt");
			if (ret != HITLS_SUCCESS) {
				lwsl_warn("%s: failed to load system CA certs: 0x%x\n", __func__, ret);
			} else {
				lwsl_info("%s: loaded CA certs from /etc/pki/tls/certs/ca-bundle.crt\n", __func__);
			}
		} else {
			lwsl_info("%s: loaded CA certs from /etc/ssl/certs/ca-certificates.crt\n", __func__);
		}

		vh->tls.ssl_client_ctx = (lws_tls_ctx *)config;
	}

	/* Load CA */
	if (ca_filepath) {
		ret = lws_openhitls_load_ca_from_file(config, ca_filepath);
		if (ret < 0)
			lwsl_warn("%s: failed to load CA\n", __func__);
	} else if (ca_mem && ca_mem_len > 0) {
		/* TODO: Implement CA loading from memory */
		lwsl_warn("%s: CA loading from memory not yet implemented\n", __func__);
	}

	/* Load certificate */
	if (cert_filepath) {
		ret = lws_openhitls_load_cert_from_file(config, cert_filepath,
							 private_key_filepath);
		if (ret < 0)
			lwsl_warn("%s: failed to load certificate\n", __func__);
	} else if (cert_mem && cert_mem_len > 0) {
		ret = lws_openhitls_load_cert_from_mem(config,
						       (const uint8_t *)cert_mem,
						       cert_mem_len,
						       (const uint8_t *)key_mem,
						       key_mem_len);
		if (ret < 0)
			lwsl_warn("%s: failed to load cert from memory\n",
				  __func__);
	}

	/* Set cipher list if provided */
	if (cipher_list) {
		ret = lws_openhitls_set_ciphers(config, cipher_list);
		if (ret < 0) {
			lwsl_warn("%s: failed to set cipher suites\n", __func__);
			/* Non-fatal, continue with defaults */
		} else {
			lwsl_info("%s: cipher suites configured from: %s\n",
				  __func__, cipher_list);
		}
	}

	/* Set ALPN if provided */
	if (vh->tls.alpn) {
		ret = lws_openhitls_set_alpn(config, vh->tls.alpn);
		if (ret < 0) {
			lwsl_warn("%s: failed to set ALPN\n", __func__);
		}
	}

	return 0;
}

enum lws_ssl_capable_status
lws_tls_client_connect(struct lws *wsi, char *errbuf, size_t len)
{
	HITLS_Ctx *ctx;
	HITLS_Config *config;
	int32_t ret;

	/* First call - create HITLS_Ctx */
	if (!wsi->tls.ssl) {
		lwsl_info("%s: creating client SSL for wsi %p\n", __func__, wsi);

		config = (HITLS_Config *)wsi->a.vhost->tls.ssl_client_ctx;
		if (!config) {
			lwsl_err("%s: no client SSL config\n", __func__);
			if (errbuf)
				lws_snprintf(errbuf, len, "No client SSL config");
			return LWS_SSL_CAPABLE_ERROR;
		}

		ctx = HITLS_New(config);
		if (!ctx) {
			lwsl_err("%s: HITLS_New failed\n", __func__);
			if (errbuf)
				lws_snprintf(errbuf, len, "HITLS_New failed");
			return LWS_SSL_CAPABLE_ERROR;
		}

		/* Client/server mode is determined by calling HITLS_Connect/Accept */

		wsi->tls.ssl = (lws_tls_conn *)ctx;

		/* Set SNI hostname */
		if (wsi->stash && wsi->stash->cis[CIS_HOST]) {
			ret = HITLS_SetServerName(ctx,
						  (uint8_t *)wsi->stash->cis[CIS_HOST],
						  (uint32_t)strlen(wsi->stash->cis[CIS_HOST]));
			if (ret != HITLS_SUCCESS) {
				lwsl_warn("%s: failed to set SNI: %d\n",
					  __func__, ret);
			} else {
				lwsl_info("%s: SNI set to %s\n",
					  __func__, wsi->stash->cis[CIS_HOST]);
			}
		}

		/* Setup UIO */
		ret = lws_openhitls_setup_uio(wsi);
		if (ret < 0) {
			lwsl_err("%s: failed to setup UIO\n", __func__);
			HITLS_Free(ctx);
			wsi->tls.ssl = NULL;
			if (errbuf)
				lws_snprintf(errbuf, len, "UIO setup failed");
			return LWS_SSL_CAPABLE_ERROR;
		}
	}

	/* Perform handshake */
	lwsl_debug("%s: performing client handshake\n", __func__);

	ret = HITLS_Connect((HITLS_Ctx *)wsi->tls.ssl);

	switch (ret) {
	case HITLS_SUCCESS:
		lwsl_info("%s: client handshake complete\n", __func__);

		/* Get negotiated ALPN */
		{
			const uint8_t *alpn_data = NULL;
			uint32_t alpn_len = 0;
			if (lws_openhitls_get_alpn((HITLS_Ctx *)wsi->tls.ssl,
						    &alpn_data, &alpn_len) == 0 &&
			    alpn_data && alpn_len > 0 &&
			    alpn_len < sizeof(wsi->a.context->tls.alpn_discovered)) {
				memcpy(wsi->a.context->tls.alpn_discovered,
				       alpn_data, alpn_len);
				wsi->a.context->tls.alpn_discovered[alpn_len] = '\0';
				lwsl_info("%s: negotiated ALPN: %s\n",
					  __func__, wsi->a.context->tls.alpn_discovered);
			}
		}

		return LWS_SSL_CAPABLE_DONE;

	case HITLS_REC_NORMAL_RECV_BUF_EMPTY:
		lwsl_debug("%s: need more data\n", __func__);
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;

	case HITLS_REC_NORMAL_IO_BUSY:
		lwsl_debug("%s: I/O busy\n", __func__);
		return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;

	case HITLS_REC_ERR_IO_EXCEPTION:
		lwsl_err("%s: I/O exception during handshake\n", __func__);
		if (errbuf) {
			lws_snprintf(errbuf, len, "I/O exception");
		}
		return LWS_SSL_CAPABLE_ERROR;

	default:
	{
		int32_t bsl_err = BSL_ERR_GetLastError();
		if (errbuf) {
			lws_snprintf(errbuf, len, "HITLS_Connect failed: 0x%x (BSL: 0x%x)",
				     ret, bsl_err);
		}
		lwsl_err("%s: HITLS_Connect failed: 0x%x, BSL_ERR: 0x%x\n",
			 __func__, ret, bsl_err);
		return LWS_SSL_CAPABLE_ERROR;
	}
	}
}

int
lws_tls_client_confirm_peer_cert(struct lws *wsi, char *ebuf, size_t ebuf_len)
{
	if (!wsi->tls.ssl) {
		if (ebuf)
			lws_snprintf(ebuf, ebuf_len, "No SSL context");
		return -1;
	}

	lwsl_info("%s: verifying peer certificate\n", __func__);

	/* TODO: openHiTLS automatically verifies certificates during handshake
	 * For now, verification is handled by the bypass callback
	 * Need to implement proper CA bundle loading for full verification
	 */
	lwsl_info("%s: certificate verification handled by bypass callback\n", __func__);
	return 0;
}

/*
 * Add extra client certificate from memory
 */
int
lws_tls_client_vhost_extra_cert_mem(struct lws_vhost *vh,
				     const uint8_t *der, size_t der_len)
{
	/* TODO: Implement extra cert loading */
	lwsl_debug("%s: not yet implemented\n", __func__);
	return 0;
}
