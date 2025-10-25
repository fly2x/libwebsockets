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
 * openHiTLS RSA implementation
 *
 * NOTE: This is a simplified implementation providing basic RSA operations
 * for JOSE (JWK/JWS/JWE) support. Full RSA functionality with all padding
 * modes and key formats may require additional development.
 */

#include "private-lib-core.h"
#include "private-lib-tls-openhitls.h"
#include <hitls/crypto/crypt_eal_pkey.h>
#include <hitls/crypto/crypt_types.h>
#include <hitls/crypto/crypt_errno.h>

/*
 * Destroy RSA key elements
 */
void
lws_genrsa_destroy_elements(struct lws_gencrypto_keyelem *el)
{
	lws_gencrypto_destroy_elements(el, LWS_GENCRYPTO_RSA_KEYEL_COUNT);
}

/*
 * Create RSA context from key elements
 *
 * NOTE: This implementation focuses on basic RSA operations needed for JOSE.
 * Advanced features like CRT (Chinese Remainder Theorem) optimization and
 * multiple padding modes may need additional work.
 */
int
lws_genrsa_create(struct lws_genrsa_ctx *ctx,
		  const struct lws_gencrypto_keyelem *el,
		  struct lws_context *context, enum enum_genrsa_mode mode,
		  enum lws_genhash_types oaep_hashid)
{
	CRYPT_EAL_PkeyCtx *pkey = NULL;
	CRYPT_EAL_PkeyPub pub_key;
	CRYPT_EAL_PkeyPrv prv_key;
	int32_t ret;

	if (!ctx || !el || !context) {
		lwsl_err("%s: invalid parameters\n", __func__);
		return -1;
	}

	memset(ctx, 0, sizeof(*ctx));
	ctx->context = context;
	ctx->mode = mode;

	/* Create RSA context */
	pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
	if (!pkey) {
		lwsl_err("%s: CRYPT_EAL_PkeyNewCtx failed\n", __func__);
		return -1;
	}

	/*
	 * Import RSA key parameters
	 *
	 * For a complete RSA private key, we need:
	 * - N (modulus)
	 * - E (public exponent)
	 * - D (private exponent)
	 * - P, Q (primes) - optional but recommended for performance
	 *
	 * For public key only, we need just N and E.
	 *
	 * TODO: This is a simplified implementation. Full support would need:
	 * - Proper handling of BIGNUMs
	 * - CRT parameters (dP, dQ, qInv)
	 * - Key validation
	 * - Support for different key sizes
	 */

	/* Setup public key */
	memset(&pub_key, 0, sizeof(pub_key));
	pub_key.id = CRYPT_PKEY_RSA;

	if (el[LWS_GENCRYPTO_RSA_KEYEL_N].buf &&
	    el[LWS_GENCRYPTO_RSA_KEYEL_N].len > 0) {
		pub_key.key.rsaPub.n = el[LWS_GENCRYPTO_RSA_KEYEL_N].buf;
		pub_key.key.rsaPub.nLen = el[LWS_GENCRYPTO_RSA_KEYEL_N].len;
	} else {
		lwsl_err("%s: missing RSA modulus (N)\n", __func__);
		goto bail;
	}

	if (el[LWS_GENCRYPTO_RSA_KEYEL_E].buf &&
	    el[LWS_GENCRYPTO_RSA_KEYEL_E].len > 0) {
		pub_key.key.rsaPub.e = el[LWS_GENCRYPTO_RSA_KEYEL_E].buf;
		pub_key.key.rsaPub.eLen = el[LWS_GENCRYPTO_RSA_KEYEL_E].len;
	} else {
		lwsl_err("%s: missing RSA public exponent (E)\n", __func__);
		goto bail;
	}

	ret = CRYPT_EAL_PkeySetPub(pkey, &pub_key);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeySetPub failed: 0x%x\n",
			 __func__, ret);
		goto bail;
	}

	/* If we have private key components, set them */
	if (el[LWS_GENCRYPTO_RSA_KEYEL_D].buf &&
	    el[LWS_GENCRYPTO_RSA_KEYEL_D].len > 0) {
		memset(&prv_key, 0, sizeof(prv_key));
		prv_key.id = CRYPT_PKEY_RSA;

		prv_key.key.rsaPrv.d = el[LWS_GENCRYPTO_RSA_KEYEL_D].buf;
		prv_key.key.rsaPrv.dLen = el[LWS_GENCRYPTO_RSA_KEYEL_D].len;

		/* Optional: P and Q for CRT optimization */
		if (el[LWS_GENCRYPTO_RSA_KEYEL_P].buf) {
			prv_key.key.rsaPrv.p = el[LWS_GENCRYPTO_RSA_KEYEL_P].buf;
			prv_key.key.rsaPrv.pLen = el[LWS_GENCRYPTO_RSA_KEYEL_P].len;
		}
		if (el[LWS_GENCRYPTO_RSA_KEYEL_Q].buf) {
			prv_key.key.rsaPrv.q = el[LWS_GENCRYPTO_RSA_KEYEL_Q].buf;
			prv_key.key.rsaPrv.qLen = el[LWS_GENCRYPTO_RSA_KEYEL_Q].len;
		}

		ret = CRYPT_EAL_PkeySetPrv(pkey, &prv_key);
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: CRYPT_EAL_PkeySetPrv failed: 0x%x\n",
				 __func__, ret);
			goto bail;
		}
	}

	ctx->ctx = (void *)pkey;
	return 0;

bail:
	if (pkey)
		CRYPT_EAL_PkeyFreeCtx(pkey);
	return -1;
}

/*
 * Generate new RSA keypair
 */
int
lws_genrsa_new_keypair(struct lws_context *context, struct lws_genrsa_ctx *ctx,
		       enum enum_genrsa_mode mode, struct lws_gencrypto_keyelem *el,
		       int bits)
{
	CRYPT_EAL_PkeyCtx *pkey = NULL;
	CRYPT_EAL_PkeyPara para;
	CRYPT_EAL_PkeyPub pub;
	CRYPT_EAL_PkeyPrv prv;
	uint8_t e_default[] = {0x01, 0x00, 0x01}; /* 65537 */
	int32_t ret;
	int n;

	if (!ctx || !context || !el) {
		lwsl_err("%s: invalid parameters\n", __func__);
		return -1;
	}

	memset(ctx, 0, sizeof(*ctx));
	ctx->context = context;
	ctx->mode = mode;

	/* Create RSA context */
	pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
	if (!pkey) {
		lwsl_err("%s: CRYPT_EAL_PkeyNewCtx failed\n", __func__);
		return -1;
	}

	/* Set RSA parameters */
	memset(&para, 0, sizeof(para));
	para.id = CRYPT_PKEY_RSA;
	para.para.rsaPara.bits = (uint32_t)bits;
	para.para.rsaPara.e = e_default;
	para.para.rsaPara.eLen = sizeof(e_default);

	ret = CRYPT_EAL_PkeySetPara(pkey, &para);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeySetPara failed: 0x%x\n",
			 __func__, ret);
		goto bail;
	}

	/* Generate key pair */
	ret = CRYPT_EAL_PkeyGen(pkey);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyGen failed: 0x%x\n",
			 __func__, ret);
		goto bail;
	}

	/* Extract public key - need to allocate buffers first
	 * Based on openHiTLS test code, use generous buffer sizes
	 * (600 bytes for 1024-bit keys, so use double for safety)
	 */
	memset(&pub, 0, sizeof(pub));
	pub.id = CRYPT_PKEY_RSA;

	/* Allocate buffer for N (modulus) - use generous size */
	pub.key.rsaPub.n = lws_malloc(512, "rsa-pub-n");
	if (!pub.key.rsaPub.n)
		goto bail;
	pub.key.rsaPub.nLen = 512;

	/* Allocate buffer for E (exponent) - usually 3 bytes but give more */
	pub.key.rsaPub.e = lws_malloc(16, "rsa-pub-e");
	if (!pub.key.rsaPub.e) {
		lws_free(pub.key.rsaPub.n);
		goto bail;
	}
	pub.key.rsaPub.eLen = 16;

	ret = CRYPT_EAL_PkeyGetPub(pkey, &pub);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyGetPub failed: 0x%x\n",
			 __func__, ret);
		lws_free(pub.key.rsaPub.n);
		lws_free(pub.key.rsaPub.e);
		goto bail;
	}

	/* Extract private key - need to allocate buffers first
	 * Use generous buffer sizes based on openHiTLS test patterns
	 */
	memset(&prv, 0, sizeof(prv));
	prv.id = CRYPT_PKEY_RSA;

	/* Need to allocate N for private key structure too */
	prv.key.rsaPrv.n = lws_malloc(512, "rsa-prv-n");
	if (!prv.key.rsaPrv.n) {
		lws_free(pub.key.rsaPub.n);
		lws_free(pub.key.rsaPub.e);
		goto bail;
	}
	prv.key.rsaPrv.nLen = 512;

	/* Allocate buffer for D (private exponent) - use generous size */
	prv.key.rsaPrv.d = lws_malloc(512, "rsa-prv-d");
	if (!prv.key.rsaPrv.d) {
		lws_free(pub.key.rsaPub.n);
		lws_free(pub.key.rsaPub.e);
		lws_free(prv.key.rsaPrv.n);
		goto bail;
	}
	prv.key.rsaPrv.dLen = 512;

	/* Allocate buffers for P and Q (primes) - generous sizes */
	prv.key.rsaPrv.p = lws_malloc(256, "rsa-prv-p");
	prv.key.rsaPrv.q = lws_malloc(256, "rsa-prv-q");
	if (!prv.key.rsaPrv.p || !prv.key.rsaPrv.q) {
		lws_free(pub.key.rsaPub.n);
		lws_free(pub.key.rsaPub.e);
		lws_free(prv.key.rsaPrv.n);
		lws_free(prv.key.rsaPrv.d);
		if (prv.key.rsaPrv.p)
			lws_free(prv.key.rsaPrv.p);
		if (prv.key.rsaPrv.q)
			lws_free(prv.key.rsaPrv.q);
		goto bail;
	}
	prv.key.rsaPrv.pLen = 256;
	prv.key.rsaPrv.qLen = 256;

	ret = CRYPT_EAL_PkeyGetPrv(pkey, &prv);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyGetPrv failed: 0x%x\n",
			 __func__, ret);
		lws_free(pub.key.rsaPub.n);
		lws_free(pub.key.rsaPub.e);
		lws_free(prv.key.rsaPrv.n);
		lws_free(prv.key.rsaPrv.d);
		lws_free(prv.key.rsaPrv.p);
		lws_free(prv.key.rsaPrv.q);
		goto bail;
	}

	/* Convert to lws_gencrypto_keyelem format */

	/* N - modulus */
	if (pub.key.rsaPub.nLen > 0) {
		el[LWS_GENCRYPTO_RSA_KEYEL_N].buf =
			lws_malloc(pub.key.rsaPub.nLen, "rsa-n");
		if (!el[LWS_GENCRYPTO_RSA_KEYEL_N].buf)
			goto bail;
		el[LWS_GENCRYPTO_RSA_KEYEL_N].len = pub.key.rsaPub.nLen;
		memcpy(el[LWS_GENCRYPTO_RSA_KEYEL_N].buf,
		       pub.key.rsaPub.n, pub.key.rsaPub.nLen);
	}

	/* E - public exponent */
	if (pub.key.rsaPub.eLen > 0) {
		el[LWS_GENCRYPTO_RSA_KEYEL_E].buf =
			lws_malloc(pub.key.rsaPub.eLen, "rsa-e");
		if (!el[LWS_GENCRYPTO_RSA_KEYEL_E].buf)
			goto bail;
		el[LWS_GENCRYPTO_RSA_KEYEL_E].len = pub.key.rsaPub.eLen;
		memcpy(el[LWS_GENCRYPTO_RSA_KEYEL_E].buf,
		       pub.key.rsaPub.e, pub.key.rsaPub.eLen);
	}

	/* D - private exponent */
	if (prv.key.rsaPrv.dLen > 0) {
		el[LWS_GENCRYPTO_RSA_KEYEL_D].buf =
			lws_malloc(prv.key.rsaPrv.dLen, "rsa-d");
		if (!el[LWS_GENCRYPTO_RSA_KEYEL_D].buf)
			goto bail;
		el[LWS_GENCRYPTO_RSA_KEYEL_D].len = prv.key.rsaPrv.dLen;
		memcpy(el[LWS_GENCRYPTO_RSA_KEYEL_D].buf,
		       prv.key.rsaPrv.d, prv.key.rsaPrv.dLen);
	}

	/* P - first prime */
	if (prv.key.rsaPrv.pLen > 0) {
		el[LWS_GENCRYPTO_RSA_KEYEL_P].buf =
			lws_malloc(prv.key.rsaPrv.pLen, "rsa-p");
		if (!el[LWS_GENCRYPTO_RSA_KEYEL_P].buf)
			goto bail;
		el[LWS_GENCRYPTO_RSA_KEYEL_P].len = prv.key.rsaPrv.pLen;
		memcpy(el[LWS_GENCRYPTO_RSA_KEYEL_P].buf,
		       prv.key.rsaPrv.p, prv.key.rsaPrv.pLen);
	}

	/* Q - second prime */
	if (prv.key.rsaPrv.qLen > 0) {
		el[LWS_GENCRYPTO_RSA_KEYEL_Q].buf =
			lws_malloc(prv.key.rsaPrv.qLen, "rsa-q");
		if (!el[LWS_GENCRYPTO_RSA_KEYEL_Q].buf)
			goto bail;
		el[LWS_GENCRYPTO_RSA_KEYEL_Q].len = prv.key.rsaPrv.qLen;
		memcpy(el[LWS_GENCRYPTO_RSA_KEYEL_Q].buf,
		       prv.key.rsaPrv.q, prv.key.rsaPrv.qLen);
	}

	ctx->ctx = (void *)pkey;

	/* Free temporary buffers */
	lws_free(pub.key.rsaPub.n);
	lws_free(pub.key.rsaPub.e);
	lws_free(prv.key.rsaPrv.n);
	lws_free(prv.key.rsaPrv.d);
	lws_free(prv.key.rsaPrv.p);
	lws_free(prv.key.rsaPrv.q);

	return 0;

bail:
	for (n = 0; n < LWS_GENCRYPTO_RSA_KEYEL_COUNT; n++)
		if (el[n].buf)
			lws_free_set_NULL(el[n].buf);
	if (pkey)
		CRYPT_EAL_PkeyFreeCtx(pkey);
	return -1;
}

/*
 * Public key encryption
 *
 * NOTE: Currently implements basic PKCS#1 v1.5 padding.
 * OAEP padding support would require additional work.
 */
int
lws_genrsa_public_encrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			  size_t in_len, uint8_t *out)
{
	uint32_t outLen;
	int32_t ret;
	int32_t hashId = CRYPT_MD_SHA256; /* Hash for MGF1 in PKCS#1 v1.5 */

	if (!ctx || !ctx->ctx || !in || !out) {
		lwsl_err("%s: invalid parameters\n", __func__);
		return -1;
	}

	/* Set encryption padding mode to PKCS#1 v1.5 (RSAES-PKCSV15) with hash */
	ret = CRYPT_EAL_PkeyCtrl((CRYPT_EAL_PkeyCtx *)ctx->ctx,
				  CRYPT_CTRL_SET_RSA_RSAES_PKCSV15,
				  &hashId, sizeof(hashId));
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: failed to set padding mode: 0x%x\n",
			 __func__, ret);
		return -1;
	}

	outLen = 4096; /* Max RSA output size - TODO: get from key size */

	ret = CRYPT_EAL_PkeyEncrypt((CRYPT_EAL_PkeyCtx *)ctx->ctx,
				     in, (uint32_t)in_len, out, &outLen);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyEncrypt failed: 0x%x\n",
			 __func__, ret);
		return -1;
	}

	return (int)outLen;
}

/*
 * Private key decryption
 */
int
lws_genrsa_private_decrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			   size_t in_len, uint8_t *out, size_t out_max)
{
	uint32_t outLen = (uint32_t)out_max;
	int32_t ret;
	int32_t hashId = CRYPT_MD_SHA256; /* Hash for MGF1 in PKCS#1 v1.5 */

	if (!ctx || !ctx->ctx || !in || !out) {
		lwsl_err("%s: invalid parameters\n", __func__);
		return -1;
	}

	/* Set decryption padding mode to PKCS#1 v1.5 (RSAES-PKCSV15) with hash */
	ret = CRYPT_EAL_PkeyCtrl((CRYPT_EAL_PkeyCtx *)ctx->ctx,
				  CRYPT_CTRL_SET_RSA_RSAES_PKCSV15,
				  &hashId, sizeof(hashId));
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: failed to set padding mode: 0x%x\n",
			 __func__, ret);
		return -1;
	}

	ret = CRYPT_EAL_PkeyDecrypt((CRYPT_EAL_PkeyCtx *)ctx->ctx,
				     in, (uint32_t)in_len, out, &outLen);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyDecrypt failed: 0x%x\n",
			 __func__, ret);
		return -1;
	}

	return (int)outLen;
}

/*
 * Private key encryption (for signing without hash)
 *
 * NOTE: openHiTLS does not provide raw RSA private encryption API.
 * This is intentional as raw RSA operations are considered insecure.
 * Use lws_genrsa_hash_sign() for proper signature operations.
 */
int
lws_genrsa_private_encrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			   size_t in_len, uint8_t *out)
{
	lwsl_err("%s: raw RSA private encryption not supported by openHiTLS\n",
		  __func__);
	lwsl_err("%s: use lws_genrsa_hash_sign() for proper signatures\n",
		 __func__);

	/*
	 * openHiTLS does not expose raw RSA encryption/decryption APIs
	 * as they are considered cryptographically unsafe. All RSA
	 * operations must use proper padding (PKCS#1, PSS, OAEP).
	 */
	return -1;
}

/*
 * Public key decryption (for signature verification without hash)
 *
 * NOTE: openHiTLS does not provide raw RSA public decryption API.
 * Use lws_genrsa_hash_sig_verify() for proper signature verification.
 */
int
lws_genrsa_public_decrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			  size_t in_len, uint8_t *out, size_t out_max)
{
	lwsl_err("%s: raw RSA public decryption not supported by openHiTLS\n",
		  __func__);
	lwsl_err("%s: use lws_genrsa_hash_sig_verify() for proper verification\n",
		 __func__);

	return -1;
}

/*
 * Sign hash with RSA private key
 *
 * TODO: Full implementation requires proper padding mode support
 * (PKCS#1 v1.5 vs PSS)
 */
int
lws_genrsa_hash_sign(struct lws_genrsa_ctx *ctx, const uint8_t *in,
		       enum lws_genhash_types hash_type, uint8_t *sig,
		       size_t sig_len)
{
	CRYPT_MD_AlgId md_id;
	uint32_t sigLen = (uint32_t)sig_len;
	int32_t ret;

	if (!ctx || !ctx->ctx || !in || !sig) {
		lwsl_err("%s: invalid parameters\n", __func__);
		return -1;
	}

	md_id = lws_gencrypto_openhitls_hash_to_MD_ID(hash_type);
	if (md_id == CRYPT_MD_MAX) {
		lwsl_err("%s: unsupported hash type\n", __func__);
		return -1;
	}

	/* Set signature padding mode to PKCS#1 v1.5 with hash algorithm */
	ret = CRYPT_EAL_PkeyCtrl((CRYPT_EAL_PkeyCtx *)ctx->ctx,
				  CRYPT_CTRL_SET_RSA_EMSA_PKCSV15,
				  &md_id, sizeof(md_id));
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: failed to set signature padding mode: 0x%x\n",
			 __func__, ret);
		return -1;
	}

	/* Sign the hash */
	ret = CRYPT_EAL_PkeySignData((CRYPT_EAL_PkeyCtx *)ctx->ctx,
				      in, (uint32_t)lws_genhash_size(hash_type),
				      sig, &sigLen);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeySignData failed: 0x%x\n",
			 __func__, ret);
		return -1;
	}

	return (int)sigLen;
}

/*
 * Verify RSA signature of hash
 */
int
lws_genrsa_hash_sig_verify(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			 enum lws_genhash_types hash_type, const uint8_t *sig,
			 size_t sig_len)
{
	CRYPT_MD_AlgId md_id;
	int32_t ret;

	if (!ctx || !ctx->ctx || !in || !sig) {
		lwsl_err("%s: invalid parameters\n", __func__);
		return -1;
	}

	md_id = lws_gencrypto_openhitls_hash_to_MD_ID(hash_type);
	if (md_id == CRYPT_MD_MAX) {
		lwsl_err("%s: unsupported hash type\n", __func__);
		return -1;
	}

	/* Set signature padding mode to PKCS#1 v1.5 with hash algorithm */
	ret = CRYPT_EAL_PkeyCtrl((CRYPT_EAL_PkeyCtx *)ctx->ctx,
				  CRYPT_CTRL_SET_RSA_EMSA_PKCSV15,
				  &md_id, sizeof(md_id));
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: failed to set signature padding mode: 0x%x\n",
			 __func__, ret);
		return -1;
	}

	ret = CRYPT_EAL_PkeyVerifyData((CRYPT_EAL_PkeyCtx *)ctx->ctx,
					in, (uint32_t)lws_genhash_size(hash_type),
					sig, (uint32_t)sig_len);
	if (ret != CRYPT_SUCCESS) {
		lwsl_notice("%s: signature verification failed: 0x%x\n",
			    __func__, ret);
		return -1;
	}

	return 0;
}

/*
 * Destroy RSA context
 */
void
lws_genrsa_destroy(struct lws_genrsa_ctx *ctx)
{
	if (!ctx || !ctx->ctx)
		return;

	CRYPT_EAL_PkeyFreeCtx((CRYPT_EAL_PkeyCtx *)ctx->ctx);
	ctx->ctx = NULL;
}
