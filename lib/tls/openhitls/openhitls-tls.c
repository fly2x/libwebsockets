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
 * openHiTLS TLS library initialization
 */

#include "private-lib-core.h"
#include "private-lib-tls-openhitls.h"

int
lws_context_init_ssl_library(struct lws_context *cx,
			      const struct lws_context_creation_info *info)
{
	int32_t ret;

	lwsl_info("%s: openHiTLS library initialization\n", __func__);

	/* Initialize all crypto components using unified API
	 * Note: CRYPT_EAL_Cleanup doesn't fully reset state, so this may return
	 * "already initialized" (0x104000a) on subsequent calls, which is OK */
	ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);

	if (ret != HITLS_SUCCESS && ret != 0x104000a) {
		/* 0x104000a = already initialized, which is acceptable */
		lwsl_err("%s: CRYPT_EAL_Init failed: 0x%x\n", __func__, ret);
		return -1;
	}

	if (ret == 0x104000a) {
		lwsl_info("%s: CRYPT_EAL already initialized (0x%x)\n", __func__, ret);
	}

	/* Always initialize certificate and crypto methods, even if CRYPT_EAL was
	 * already initialized. These calls are idempotent and required for proper
	 * operation after CRYPT_EAL_Cleanup */
	HITLS_CertMethodInit();
	HITLS_CryptMethodInit();

	lwsl_info("%s: openHiTLS initialized successfully\n", __func__);

	return 0;
}

void
lws_context_deinit_ssl_library(struct lws_context *context)
{
	lwsl_info("%s: openHiTLS library deinitialization\n", __func__);

	/* Note: We intentionally do NOT call CRYPT_EAL_Cleanup here.
	 * openHiTLS has a limitation where calling CRYPT_EAL_Cleanup and then
	 * CRYPT_EAL_Init again causes HITLS_CFG_NewTLSConfig to fail with
	 * error 0x3040001, even after re-calling the method init functions.
	 *
	 * This is safe because:
	 * 1. CRYPT_EAL_Init is idempotent - subsequent calls return success
	 * 2. The crypto library can safely remain initialized for process lifetime
	 * 3. This matches the pattern used by other TLS backends (OpenSSL, etc.)
	 *
	 * The openHiTLS library will be cleaned up when the process exits.
	 */

	lwsl_info("%s: openHiTLS context deinitialized (crypto lib remains active)\n", __func__);
}

void
lws_ssl_destroy(struct lws_vhost *vhost)
{
	if (!vhost->tls.ssl_ctx)
		return;

	lwsl_info("%s: destroying SSL context for vhost %s\n",
		  __func__, vhost->name);

	HITLS_CFG_FreeConfig((HITLS_Config *)vhost->tls.ssl_ctx);
	vhost->tls.ssl_ctx = NULL;
}

void
lws_ssl_SSL_CTX_destroy(struct lws_vhost *vhost)
{
	if (vhost->tls.ssl_ctx) {
		HITLS_CFG_FreeConfig((HITLS_Config *)vhost->tls.ssl_ctx);
		vhost->tls.ssl_ctx = NULL;
	}

	if (vhost->tls.ssl_client_ctx) {
		HITLS_CFG_FreeConfig((HITLS_Config *)vhost->tls.ssl_client_ctx);
		vhost->tls.ssl_client_ctx = NULL;
	}
}

void
lws_ssl_context_destroy(struct lws_context *context)
{
	struct lws_vhost *vh = context->vhost_list;

	while (vh) {
		if (vh->tls.ssl_ctx)
			lws_ssl_SSL_CTX_destroy(vh);
		vh = vh->vhost_next;
	}
}

lws_tls_ctx *
lws_tls_ctx_from_wsi(struct lws *wsi)
{
	if (!wsi->tls.use_ssl)
		return NULL;

	return wsi->a.vhost->tls.ssl_client_ctx ?
	       wsi->a.vhost->tls.ssl_client_ctx :
	       wsi->a.vhost->tls.ssl_ctx;
}

/* Helper function to parse cipher list string and set cipher suites */
int
lws_openhitls_set_ciphers(HITLS_Config *config, const char *cipher_list)
{
	uint16_t ciphersuites[64];  /* Support up to 64 cipher suites */
	uint32_t count = 0;
	int32_t ret;

	if (!config || !cipher_list) {
		lwsl_err("%s: invalid parameters\n", __func__);
		return -1;
	}

	lwsl_info("%s: parsing cipher list: %s\n", __func__, cipher_list);

	/*
	 * Parse cipher list string. For simplicity, we'll support common
	 * predefined groups:
	 * - "HIGH" or "DEFAULT": Strong modern cipher suites
	 * - "ALL": All supported cipher suites
	 * - Specific cipher names (TLS 1.3 style)
	 *
	 * OpenSSL-style cipher strings like "HIGH:!aNULL" are complex to parse,
	 * so we'll support the most common cases.
	 */

	if (strstr(cipher_list, "ALL") != NULL) {
		/* Use all available cipher suites */
		ciphersuites[count++] = HITLS_AES_128_GCM_SHA256;  /* TLS 1.3 */
		ciphersuites[count++] = HITLS_AES_256_GCM_SHA384;
		ciphersuites[count++] = HITLS_CHACHA20_POLY1305_SHA256;
		ciphersuites[count++] = HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;  /* TLS 1.2 */
		ciphersuites[count++] = HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
		ciphersuites[count++] = HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
		ciphersuites[count++] = HITLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;
		ciphersuites[count++] = HITLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256;
		ciphersuites[count++] = HITLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
		ciphersuites[count++] = HITLS_DHE_RSA_WITH_AES_128_GCM_SHA256;
		ciphersuites[count++] = HITLS_DHE_RSA_WITH_AES_256_GCM_SHA384;
		ciphersuites[count++] = HITLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
		ciphersuites[count++] = HITLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256;
		ciphersuites[count++] = HITLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256;
		ciphersuites[count++] = HITLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384;
		ciphersuites[count++] = HITLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384;
		ciphersuites[count++] = HITLS_DHE_RSA_WITH_AES_128_CBC_SHA256;
		ciphersuites[count++] = HITLS_DHE_RSA_WITH_AES_256_CBC_SHA256;
	} else if (strstr(cipher_list, "DEFAULT") != NULL ||
		   strstr(cipher_list, "HIGH") != NULL) {
		/* Use secure modern cipher suites (GCM and ChaCha20) */
		ciphersuites[count++] = HITLS_AES_128_GCM_SHA256;  /* TLS 1.3 */
		ciphersuites[count++] = HITLS_AES_256_GCM_SHA384;
		ciphersuites[count++] = HITLS_CHACHA20_POLY1305_SHA256;
		ciphersuites[count++] = HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;  /* TLS 1.2 */
		ciphersuites[count++] = HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
		ciphersuites[count++] = HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
		ciphersuites[count++] = HITLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;
		ciphersuites[count++] = HITLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256;
		ciphersuites[count++] = HITLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
		ciphersuites[count++] = HITLS_DHE_RSA_WITH_AES_128_GCM_SHA256;
		ciphersuites[count++] = HITLS_DHE_RSA_WITH_AES_256_GCM_SHA384;
		ciphersuites[count++] = HITLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
	} else if (strstr(cipher_list, "TLS13") != NULL ||
		   strstr(cipher_list, "TLS_AES") != NULL) {
		/* TLS 1.3 only cipher suites */
		ciphersuites[count++] = HITLS_AES_128_GCM_SHA256;
		ciphersuites[count++] = HITLS_AES_256_GCM_SHA384;
		ciphersuites[count++] = HITLS_CHACHA20_POLY1305_SHA256;
		ciphersuites[count++] = HITLS_AES_128_CCM_SHA256;
	} else {
		/* Try to parse specific cipher names */
		if (strstr(cipher_list, "AES128-GCM-SHA256")) {
			ciphersuites[count++] = HITLS_AES_128_GCM_SHA256;
			ciphersuites[count++] = HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
			ciphersuites[count++] = HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
		}
		if (strstr(cipher_list, "AES256-GCM-SHA384")) {
			ciphersuites[count++] = HITLS_AES_256_GCM_SHA384;
			ciphersuites[count++] = HITLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;
			ciphersuites[count++] = HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
		}
		if (strstr(cipher_list, "CHACHA20")) {
			ciphersuites[count++] = HITLS_CHACHA20_POLY1305_SHA256;
			ciphersuites[count++] = HITLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
			ciphersuites[count++] = HITLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256;
		}

		/* If nothing matched, use default */
		if (count == 0) {
			lwsl_warn("%s: unrecognized cipher list, using defaults\n", __func__);
			ciphersuites[count++] = HITLS_AES_128_GCM_SHA256;
			ciphersuites[count++] = HITLS_AES_256_GCM_SHA384;
			ciphersuites[count++] = HITLS_CHACHA20_POLY1305_SHA256;
			ciphersuites[count++] = HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
			ciphersuites[count++] = HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
			ciphersuites[count++] = HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
			ciphersuites[count++] = HITLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;
		}
	}

	/* Set cipher suites in config */
	ret = HITLS_CFG_SetCipherSuites(config, ciphersuites, count);
	if (ret != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CFG_SetCipherSuites failed: 0x%x\n",
			 __func__, ret);
		return -1;
	}

	lwsl_info("%s: successfully configured %u cipher suites\n",
		  __func__, count);

	return 0;
}
