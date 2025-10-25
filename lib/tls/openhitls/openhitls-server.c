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
 * openHiTLS server-side implementation
 */

#include "private-lib-core.h"
#include "private-lib-tls-openhitls.h"

int
lws_tls_server_client_cert_verify_config(struct lws_vhost *vh)
{
	HITLS_Config *config = (HITLS_Config *)vh->tls.ssl_ctx;
	int32_t ret;

	if (!config) {
		lwsl_err("%s: no SSL config\n", __func__);
		return -1;
	}

	/*
	 * Enable client certificate verification if requested
	 * This is controlled by LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT
	 */
	if (vh->options & LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT) {
		lwsl_info("%s: enabling client certificate verification\n", __func__);

		/* Enable client certificate verification */
		ret = HITLS_CFG_SetClientVerifySupport(config, true);
		if (ret != HITLS_SUCCESS) {
			lwsl_err("%s: HITLS_CFG_SetClientVerifySupport failed: 0x%x\n",
				 __func__, ret);
			return -1;
		}

		/* Require client to provide certificate (don't allow no cert) */
		ret = HITLS_CFG_SetNoClientCertSupport(config, false);
		if (ret != HITLS_SUCCESS) {
			lwsl_err("%s: HITLS_CFG_SetNoClientCertSupport failed: 0x%x\n",
				 __func__, ret);
			return -1;
		}

		/*
		 * Load CA certificates for verifying client certificates
		 * Note: The CA file should already be loaded during vhost init
		 * via lws_openhitls_load_ca_from_file if ca_filepath was provided
		 */
		lwsl_info("%s: client certificate verification enabled\n", __func__);
	} else if (vh->options & LWS_SERVER_OPTION_PEER_CERT_NOT_REQUIRED) {
		lwsl_info("%s: client certificate optional (not required)\n", __func__);

		/* Enable verification but allow clients without certificates */
		ret = HITLS_CFG_SetClientVerifySupport(config, true);
		if (ret != HITLS_SUCCESS) {
			lwsl_warn("%s: HITLS_CFG_SetClientVerifySupport failed: 0x%x\n",
				  __func__, ret);
			/* Non-fatal */
		}

		/* Allow clients without certificates */
		ret = HITLS_CFG_SetNoClientCertSupport(config, true);
		if (ret != HITLS_SUCCESS) {
			lwsl_warn("%s: HITLS_CFG_SetNoClientCertSupport failed: 0x%x\n",
				  __func__, ret);
			/* Non-fatal */
		}
	} else {
		lwsl_info("%s: client certificate verification disabled\n", __func__);
	}

	return 0;
}

int
lws_tls_server_vhost_backend_init(const struct lws_context_creation_info *info,
				   struct lws_vhost *vhost, struct lws *wsi)
{
	HITLS_Config *config;
	int32_t ret;

	lwsl_info("%s: initializing server SSL for vhost %s\n",
		  __func__, vhost->name);

	/* Create TLS config */
	config = HITLS_CFG_NewTLSConfig();
	if (!config) {
		lwsl_err("%s: HITLS_CFG_NewTLSConfig failed\n", __func__);
		return -1;
	}

	/* Set protocol version */
	ret = HITLS_CFG_SetVersion(config, HITLS_VERSION_TLS12,
				    HITLS_VERSION_TLS13);
	if (ret != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CFG_SetVersion failed: %d\n",
			 __func__, ret);
		HITLS_CFG_FreeConfig(config);
		return -1;
	}

	/* Load server certificate if provided */
	if (info->ssl_cert_filepath) {
		ret = lws_openhitls_load_cert_from_file(config,
							 info->ssl_cert_filepath,
							 info->ssl_private_key_filepath);
		if (ret < 0) {
			lwsl_err("%s: failed to load certificate\n", __func__);
			HITLS_CFG_FreeConfig(config);
			return -1;
		}
	} else if (info->server_ssl_cert_mem && info->server_ssl_cert_mem_len) {
		ret = lws_openhitls_load_cert_from_mem(config,
						       (const uint8_t *)info->server_ssl_cert_mem,
						       (uint32_t)info->server_ssl_cert_mem_len,
						       (const uint8_t *)info->server_ssl_private_key_mem,
						       (uint32_t)info->server_ssl_private_key_mem_len);
		if (ret < 0) {
			lwsl_err("%s: failed to load certificate from memory\n",
				 __func__);
			HITLS_CFG_FreeConfig(config);
			return -1;
		}
	}

	/* Set ALPN if provided */
	if (vhost->tls.alpn) {
		ret = lws_openhitls_set_alpn(config, vhost->tls.alpn);
		if (ret < 0) {
			lwsl_warn("%s: failed to set ALPN\n", __func__);
		}
	}

	/* Set cipher suites if provided */
	if (info->ssl_cipher_list) {
		ret = lws_openhitls_set_ciphers(config, info->ssl_cipher_list);
		if (ret < 0) {
			lwsl_warn("%s: failed to set cipher suites\n", __func__);
			/* Non-fatal, continue with defaults */
		} else {
			lwsl_info("%s: cipher suites configured from: %s\n",
				  __func__, info->ssl_cipher_list);
		}
	}

	/*
	 * Load CA certificate for client certificate verification (mTLS)
	 * This is needed when LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT
	 * is set
	 */
	if (info->ssl_ca_filepath) {
		ret = lws_openhitls_load_ca_from_file(config, info->ssl_ca_filepath);
		if (ret < 0) {
			lwsl_warn("%s: failed to load CA certificate from %s\n",
				  __func__, info->ssl_ca_filepath);
			/* Non-fatal if client cert verification not required */
		} else {
			lwsl_info("%s: loaded CA certificate from %s\n",
				  __func__, info->ssl_ca_filepath);
		}
	}

	/* Enable session cache */
	ret = HITLS_CFG_SetSessionCacheMode(config,
					    HITLS_SESS_CACHE_SERVER);
	if (ret != HITLS_SUCCESS) {
		lwsl_warn("%s: failed to enable session cache\n", __func__);
	}

	/* Save config to vhost */
	vhost->tls.ssl_ctx = (lws_tls_ctx *)config;
	vhost->tls.use_ssl = 1;

	lwsl_info("%s: server SSL initialization complete\n", __func__);

	return 0;
}

int
lws_tls_server_new_nonblocking(struct lws *wsi, lws_sockfd_type accept_fd)
{
	HITLS_Ctx *ctx;
	HITLS_Config *config;
	int32_t ret;

	lwsl_info("%s: creating new server SSL for wsi %p\n", __func__, wsi);

	/* Get config from vhost */
	config = (HITLS_Config *)wsi->a.vhost->tls.ssl_ctx;
	if (!config) {
		lwsl_err("%s: no SSL config\n", __func__);
		return -1;
	}

	/* Create HITLS_Ctx */
	ctx = HITLS_New(config);
	if (!ctx) {
		lwsl_err("%s: HITLS_New failed\n", __func__);
		return -1;
	}

	/* Set as server endpoint */
	ret = HITLS_SetEndPoint(ctx, false);  /* false = server */
	if (ret != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_SetEndPoint failed: %d\n", __func__, ret);
		HITLS_Free(ctx);
		return -1;
	}

	/* Save to wsi */
	wsi->tls.ssl = (lws_tls_conn *)ctx;

	/* Setup UIO */
	ret = lws_openhitls_setup_uio(wsi);
	if (ret < 0) {
		lwsl_err("%s: failed to setup UIO\n", __func__);
		HITLS_Free(ctx);
		wsi->tls.ssl = NULL;
		return -1;
	}

	lwsl_info("%s: server SSL created successfully\n", __func__);

	return 0;
}

enum lws_ssl_capable_status
lws_tls_server_accept(struct lws *wsi)
{
	int32_t ret;

	if (!wsi->tls.ssl) {
		lwsl_err("%s: no SSL context\n", __func__);
		return LWS_SSL_CAPABLE_ERROR;
	}

	lwsl_debug("%s: accepting server handshake\n", __func__);

	ret = HITLS_Accept((HITLS_Ctx *)wsi->tls.ssl);

	switch (ret) {
	case HITLS_SUCCESS:
		lwsl_info("%s: server handshake complete\n", __func__);

		/* Get negotiated ALPN if available */
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

	default:
		lwsl_err("%s: HITLS_Accept failed: 0x%x\n",
			 __func__, ret);
		lws_tls_err_describe_clear();
		return LWS_SSL_CAPABLE_ERROR;
	}
}

enum lws_ssl_capable_status
lws_tls_server_abort_connection(struct lws *wsi)
{
	if (!wsi->tls.ssl)
		return LWS_SSL_CAPABLE_DONE;

	lwsl_info("%s: aborting connection\n", __func__);

	/* Send fatal alert */
	HITLS_Close((HITLS_Ctx *)wsi->tls.ssl);

	return LWS_SSL_CAPABLE_DONE;
}
