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
 * openHiTLS generic crypto helper functions
 */

#include "private-lib-core.h"
#include <hitls/crypto/crypt_algid.h>

/*
 * Map libwebsockets hash types to openHiTLS MD algorithm IDs
 */
CRYPT_MD_AlgId
lws_gencrypto_openhitls_hash_to_MD_ID(enum lws_genhash_types hash_type)
{
	switch (hash_type) {
	case LWS_GENHASH_TYPE_SHA1:
		return CRYPT_MD_SHA1;
	case LWS_GENHASH_TYPE_SHA256:
		return CRYPT_MD_SHA256;
	case LWS_GENHASH_TYPE_SHA384:
		return CRYPT_MD_SHA384;
	case LWS_GENHASH_TYPE_SHA512:
		return CRYPT_MD_SHA512;
	case LWS_GENHASH_TYPE_MD5:
		return CRYPT_MD_MD5;
	default:
		return CRYPT_MD_MAX;
	}
}

/*
 * Map libwebsockets hash types to openHiTLS MAC algorithm IDs
 */
CRYPT_MAC_AlgId
lws_gencrypto_openhitls_hash_to_HMAC_ID(enum lws_genhmac_types hmac_type)
{
	switch (hmac_type) {
	case LWS_GENHMAC_TYPE_SHA256:
		return CRYPT_MAC_HMAC_SHA256;
	case LWS_GENHMAC_TYPE_SHA384:
		return CRYPT_MAC_HMAC_SHA384;
	case LWS_GENHMAC_TYPE_SHA512:
		return CRYPT_MAC_HMAC_SHA512;
	default:
		return CRYPT_MAC_MAX;
	}
}

/* lws_gencrypto_destroy_elements is provided by lws-gencrypto-common.c */
