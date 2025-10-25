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
 * openHiTLS-specific helper declarations
 */

#if !defined(__LWS_PRIVATE_LIB_TLS_OPENHITLS_H__)
#define __LWS_PRIVATE_LIB_TLS_OPENHITLS_H__

#include <hitls/bsl/bsl_uio.h>
#include <hitls/tls/hitls.h>
#include <hitls/tls/hitls_error.h>
#include <hitls/tls/hitls_cert_init.h>
#include <hitls/tls/hitls_crypt_init.h>
#include <hitls/tls/hitls_alpn.h>
#include <hitls/crypto/crypt_eal_init.h>

/*
 * X509 certificate representation for openHiTLS
 * openHiTLS uses raw certificate data instead of X509 structures
 */
struct lws_x509_cert {
	uint8_t *cert_data;
	uint32_t cert_len;
	HITLS_ParseFormat format;
};

/*
 * UIO context for storing UIO state
 * Note: The UIO method is managed internally by openHiTLS
 */
struct lws_openhitls_uio_ctx {
	BSL_UIO *uio;
};

/*
 * Helper functions
 */

/* Certificate and key loading */
int lws_openhitls_load_cert_from_file(HITLS_Config *config,
				       const char *cert_path,
				       const char *key_path);

int lws_openhitls_load_ca_from_file(HITLS_Config *config,
				     const char *ca_path);

int lws_openhitls_load_cert_from_mem(HITLS_Config *config,
				      const uint8_t *cert_data,
				      uint32_t cert_len,
				      const uint8_t *key_data,
				      uint32_t key_len);

/* UIO adapter */
int lws_openhitls_setup_uio(struct lws *wsi);
void lws_openhitls_destroy_uio(struct lws *wsi);

/* ALPN support */
int lws_openhitls_set_alpn(HITLS_Config *config, const char *alpn);
int lws_openhitls_get_alpn(HITLS_Ctx *ctx, const uint8_t **data,
			    uint32_t *len);

/* Cipher suite configuration */
int lws_openhitls_set_ciphers(HITLS_Config *config, const char *cipher_list);

/* Error handling */
const char *lws_openhitls_error_string(int32_t err);

/* File I/O helpers */
int lws_read_file_to_buffer(const char *path, uint8_t **buf, size_t *len);

/* Crypto helper functions */
#if defined(LWS_WITH_GENCRYPTO)
#include <hitls/crypto/crypt_algid.h>

CRYPT_MD_AlgId lws_gencrypto_openhitls_hash_to_MD_ID(enum lws_genhash_types hash_type);
CRYPT_MAC_AlgId lws_gencrypto_openhitls_hash_to_HMAC_ID(enum lws_genhmac_types hmac_type);
void lws_gencrypto_destroy_elements(struct lws_gencrypto_keyelem *el, int count);
#endif

#endif /* __LWS_PRIVATE_LIB_TLS_OPENHITLS_H__ */
