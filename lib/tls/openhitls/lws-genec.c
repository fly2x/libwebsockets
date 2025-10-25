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
 * openHiTLS Elliptic Curve implementation
 *
 * NOTE: This is a simplified implementation providing basic EC operations
 * for JOSE (JWK/JWS/JWE) support, focusing on ECDH and ECDSA.
 */

#include "private-lib-core.h"
#include "private-lib-tls-openhitls.h"
#include <hitls/crypto/crypt_eal_pkey.h>
#include <hitls/crypto/crypt_types.h>
#include <hitls/crypto/crypt_errno.h>

/*
 * Standard EC curves supported - matching libwebsockets conventions
 */
const struct lws_ec_curves lws_ec_curves[] = {
	{ "P-256", CRYPT_ECC_NISTP256, 32 },
	{ "P-384", CRYPT_ECC_NISTP384, 48 },
	{ "P-521", CRYPT_ECC_NISTP521, 66 },
	{ NULL, 0, 0 }
};

/*
 * Find curve by name
 */
const struct lws_ec_curves *
lws_genec_curve(const struct lws_ec_curves *table, const char *name)
{
	const struct lws_ec_curves *c = table;

	while (c->name) {
		if (!strcmp(c->name, name))
			return c;
		c++;
	}

	return NULL;
}

/*
 * Create ECDH context
 */
int
lws_genecdh_create(struct lws_genec_ctx *ctx, struct lws_context *context,
		   const struct lws_ec_curves *curve_table)
{
	if (!ctx || !context) {
		lwsl_err("%s: invalid parameters\n", __func__);
		return -1;
	}

	memset(ctx, 0, sizeof(*ctx));
	ctx->context = context;
	ctx->curve_table = curve_table ? curve_table : lws_ec_curves;
	ctx->genec_alg = LEGENEC_ECDH;

	return 0;
}

/*
 * Create ECDSA context
 */
int
lws_genecdsa_create(struct lws_genec_ctx *ctx, struct lws_context *context,
		    const struct lws_ec_curves *curve_table)
{
	if (!ctx || !context) {
		lwsl_err("%s: invalid parameters\n", __func__);
		return -1;
	}

	memset(ctx, 0, sizeof(*ctx));
	ctx->context = context;
	ctx->curve_table = curve_table ? curve_table : lws_ec_curves;
	ctx->genec_alg = LEGENEC_ECDSA;

	return 0;
}

/*
 * Set EC key for ECDH
 */
int
lws_genecdh_set_key(struct lws_genec_ctx *ctx, struct lws_gencrypto_keyelem *el,
		    enum enum_lws_dh_side side)
{
	CRYPT_EAL_PkeyCtx *pkey = NULL;
	CRYPT_EAL_PkeyPub pub_key;
	CRYPT_EAL_PkeyPrv prv_key;
	const struct lws_ec_curves *curve;
	uint8_t *pubkey_buf = NULL;
	uint32_t pubkey_len;
	int32_t ret;

	if (!ctx || !el || ctx->genec_alg != LEGENEC_ECDH) {
		lwsl_err("%s: invalid parameters or not ECDH context\n", __func__);
		return -1;
	}

	/* Get curve info */
	if (!el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf) {
		lwsl_err("%s: curve name not provided\n", __func__);
		return -1;
	}

	curve = lws_genec_curve(ctx->curve_table,
				(const char *)el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf);
	if (!curve) {
		lwsl_err("%s: unsupported curve: %s\n", __func__,
			 el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf);
		return -1;
	}

	/* Create EC context */
	pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDH);
	if (!pkey) {
		lwsl_err("%s: CRYPT_EAL_PkeyNewCtx failed\n", __func__);
		return -1;
	}

	/* Set curve parameter */
	ret = CRYPT_EAL_PkeySetParaById(pkey, curve->tls_lib_nid);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeySetParaById failed: 0x%x\n",
			 __func__, ret);
		goto bail;
	}

	/* Set public key (X, Y coordinates) */
	if (el[LWS_GENCRYPTO_EC_KEYEL_X].buf &&
	    el[LWS_GENCRYPTO_EC_KEYEL_Y].buf) {
		/*
		 * openHiTLS expects public key in uncompressed format:
		 * 0x04 || X || Y
		 */
		pubkey_len = 1 + el[LWS_GENCRYPTO_EC_KEYEL_X].len +
			     el[LWS_GENCRYPTO_EC_KEYEL_Y].len;
		pubkey_buf = lws_malloc(pubkey_len, "ec-pub-temp");
		if (!pubkey_buf)
			goto bail;

		pubkey_buf[0] = 0x04; /* Uncompressed point format */
		memcpy(pubkey_buf + 1,
		       el[LWS_GENCRYPTO_EC_KEYEL_X].buf,
		       el[LWS_GENCRYPTO_EC_KEYEL_X].len);
		memcpy(pubkey_buf + 1 + el[LWS_GENCRYPTO_EC_KEYEL_X].len,
		       el[LWS_GENCRYPTO_EC_KEYEL_Y].buf,
		       el[LWS_GENCRYPTO_EC_KEYEL_Y].len);

		memset(&pub_key, 0, sizeof(pub_key));
		pub_key.id = CRYPT_PKEY_ECDH;
		pub_key.key.eccPub.data = pubkey_buf;
		pub_key.key.eccPub.len = pubkey_len;

		ret = CRYPT_EAL_PkeySetPub(pkey, &pub_key);
		lws_free(pubkey_buf);
		pubkey_buf = NULL;

		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: CRYPT_EAL_PkeySetPub failed: 0x%x\n",
				 __func__, ret);
			goto bail;
		}
	}

	/* Set private key if available */
	if (el[LWS_GENCRYPTO_EC_KEYEL_D].buf &&
	    el[LWS_GENCRYPTO_EC_KEYEL_D].len > 0) {
		memset(&prv_key, 0, sizeof(prv_key));
		prv_key.id = CRYPT_PKEY_ECDH;
		prv_key.key.eccPrv.data = el[LWS_GENCRYPTO_EC_KEYEL_D].buf;
		prv_key.key.eccPrv.len = el[LWS_GENCRYPTO_EC_KEYEL_D].len;

		ret = CRYPT_EAL_PkeySetPrv(pkey, &prv_key);
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: CRYPT_EAL_PkeySetPrv failed: 0x%x\n",
				 __func__, ret);
			goto bail;
		}
		ctx->has_private = 1;
	}

	ctx->ctx[side] = (void *)pkey;
	return 0;

bail:
	if (pubkey_buf)
		lws_free(pubkey_buf);
	if (pkey)
		CRYPT_EAL_PkeyFreeCtx(pkey);
	return -1;
}

/*
 * Set EC key for ECDSA
 */
int
lws_genecdsa_set_key(struct lws_genec_ctx *ctx,
		     const struct lws_gencrypto_keyelem *el)
{
	if (!ctx || ctx->genec_alg != LEGENEC_ECDSA) {
		lwsl_err("%s: invalid parameters or not ECDSA context\n", __func__);
		return -1;
	}

	/* Reuse ECDH key setting logic, just use ECDSA algorithm */
	return lws_genecdh_set_key(ctx, (struct lws_gencrypto_keyelem *)el,
				   LDHS_OURS);
}

/*
 * Generate new ECDH keypair
 */
int
lws_genecdh_new_keypair(struct lws_genec_ctx *ctx, enum enum_lws_dh_side side,
			const char *curve_name,
			struct lws_gencrypto_keyelem *el)
{
	CRYPT_EAL_PkeyCtx *pkey = NULL;
	CRYPT_EAL_PkeyPub pub;
	CRYPT_EAL_PkeyPrv prv;
	const struct lws_ec_curves *curve;
	int32_t ret;
	int n;

	if (!ctx || (ctx->genec_alg != LEGENEC_ECDH && ctx->genec_alg != LEGENEC_ECDSA) ||
	    !curve_name || !el) {
		lwsl_err("%s: invalid parameters or not EC context\n", __func__);
		return -1;
	}

	/* Find curve */
	curve = lws_genec_curve(ctx->curve_table, curve_name);
	if (!curve) {
		lwsl_err("%s: unsupported curve: %s\n", __func__, curve_name);
		return -1;
	}

	/* Create EC context (ECDH or ECDSA) */
	pkey = CRYPT_EAL_PkeyNewCtx(ctx->genec_alg == LEGENEC_ECDH ?
				     CRYPT_PKEY_ECDH : CRYPT_PKEY_ECDSA);
	if (!pkey) {
		lwsl_err("%s: CRYPT_EAL_PkeyNewCtx failed\n", __func__);
		return -1;
	}

	/* Set curve parameter */
	ret = CRYPT_EAL_PkeySetParaById(pkey, curve->tls_lib_nid);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeySetParaById failed: 0x%x\n",
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

	/* Extract public key - pre-allocate buffer based on curve */
	memset(&pub, 0, sizeof(pub));
	pub.id = (ctx->genec_alg == LEGENEC_ECDH) ? CRYPT_PKEY_ECDH : CRYPT_PKEY_ECDSA;
	/* For uncompressed point: (key_bytes * 2) + 1 */
	pub.key.eccPub.len = (uint32_t)((curve->key_bytes * 2) + 1);
	pub.key.eccPub.data = lws_malloc(pub.key.eccPub.len, "ec-pub-temp");
	if (!pub.key.eccPub.data)
		goto bail;

	ret = CRYPT_EAL_PkeyGetPub(pkey, &pub);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyGetPub failed: 0x%x\n",
			 __func__, ret);
		lws_free(pub.key.eccPub.data);
		goto bail;
	}

	/* Extract private key - pre-allocate buffer */
	memset(&prv, 0, sizeof(prv));
	prv.id = (ctx->genec_alg == LEGENEC_ECDH) ? CRYPT_PKEY_ECDH : CRYPT_PKEY_ECDSA;
	prv.key.eccPrv.len = (uint32_t)curve->key_bytes;
	prv.key.eccPrv.data = lws_malloc(prv.key.eccPrv.len, "ec-prv-temp");
	if (!prv.key.eccPrv.data) {
		lws_free(pub.key.eccPub.data);
		goto bail;
	}

	ret = CRYPT_EAL_PkeyGetPrv(pkey, &prv);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyGetPrv failed: 0x%x\n",
			 __func__, ret);
		lws_free(pub.key.eccPub.data);
		lws_free(prv.key.eccPrv.data);
		goto bail;
	}

	/* Store curve name */
	el[LWS_GENCRYPTO_EC_KEYEL_CRV].len = (uint32_t)strlen(curve_name) + 1;
	el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf =
		lws_malloc(el[LWS_GENCRYPTO_EC_KEYEL_CRV].len, "ec-crv");
	if (!el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf)
		goto bail;
	strcpy((char *)el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf, curve_name);

	/*
	 * openHiTLS returns EC public key in uncompressed format (04 || X || Y)
	 * We need to split into X and Y components
	 */
	if (pub.key.eccPub.len > 0 && pub.key.eccPub.data[0] == 0x04) {
		/* Uncompressed point: skip 0x04 byte, then X and Y each are curve->key_bytes */
		uint32_t coord_len = (pub.key.eccPub.len - 1) / 2;

		/* X coordinate */
		el[LWS_GENCRYPTO_EC_KEYEL_X].len = coord_len;
		el[LWS_GENCRYPTO_EC_KEYEL_X].buf = lws_malloc(coord_len, "ec-x");
		if (!el[LWS_GENCRYPTO_EC_KEYEL_X].buf)
			goto bail;
		memcpy(el[LWS_GENCRYPTO_EC_KEYEL_X].buf,
		       pub.key.eccPub.data + 1, coord_len);

		/* Y coordinate */
		el[LWS_GENCRYPTO_EC_KEYEL_Y].len = coord_len;
		el[LWS_GENCRYPTO_EC_KEYEL_Y].buf = lws_malloc(coord_len, "ec-y");
		if (!el[LWS_GENCRYPTO_EC_KEYEL_Y].buf)
			goto bail;
		memcpy(el[LWS_GENCRYPTO_EC_KEYEL_Y].buf,
		       pub.key.eccPub.data + 1 + coord_len, coord_len);
	} else {
		lwsl_err("%s: unexpected public key format\n", __func__);
		goto bail;
	}

	/* D - private key */
	if (prv.key.eccPrv.len > 0) {
		el[LWS_GENCRYPTO_EC_KEYEL_D].len = prv.key.eccPrv.len;
		el[LWS_GENCRYPTO_EC_KEYEL_D].buf =
			lws_malloc(prv.key.eccPrv.len, "ec-d");
		if (!el[LWS_GENCRYPTO_EC_KEYEL_D].buf)
			goto bail;
		memcpy(el[LWS_GENCRYPTO_EC_KEYEL_D].buf,
		       prv.key.eccPrv.data, prv.key.eccPrv.len);
	}

	/* Free temporary buffers */
	lws_free(pub.key.eccPub.data);
	lws_free(prv.key.eccPrv.data);

	ctx->ctx[side] = (void *)pkey;
	ctx->has_private = 1;
	return 0;

bail:
	for (n = 0; n < LWS_GENCRYPTO_EC_KEYEL_COUNT; n++)
		if (el[n].buf)
			lws_free_set_NULL(el[n].buf);
	if (pkey)
		CRYPT_EAL_PkeyFreeCtx(pkey);
	return -1;
}

/*
 * Generate new ECDSA keypair
 */
int
lws_genecdsa_new_keypair(struct lws_genec_ctx *ctx, const char *curve_name,
			 struct lws_gencrypto_keyelem *el)
{
	if (!ctx || ctx->genec_alg != LEGENEC_ECDSA) {
		lwsl_err("%s: invalid parameters or not ECDSA context\n", __func__);
		return -1;
	}

	return lws_genecdh_new_keypair(ctx, LDHS_OURS, curve_name, el);
}

/*
 * Parse DER-encoded ECDSA signature to extract R and S values
 * DER format: 30 [total-len] 02 [r-len] [r-bytes] 02 [s-len] [s-bytes]
 */
static int
parse_der_sig(const uint8_t *der, size_t der_len, uint8_t *r, size_t *r_len,
	      uint8_t *s, size_t *s_len)
{
	size_t pos = 0;

	/* Check SEQUENCE tag */
	if (der[pos++] != 0x30)
		return -1;

	/* Skip sequence length */
	if (der[pos] & 0x80) {
		/* Multi-byte length - skip for simplicity */
		size_t len_bytes = (size_t)(der[pos++] & 0x7f);
		pos += len_bytes;
	} else {
		pos++; /* Single byte length */
	}

	/* Parse R */
	if (der[pos++] != 0x02) /* INTEGER tag */
		return -1;

	*r_len = der[pos++];
	/* Skip leading zero if present (for positive sign) */
	if (der[pos] == 0x00 && *r_len > 1) {
		pos++;
		(*r_len)--;
	}
	memcpy(r, der + pos, *r_len);
	pos += *r_len;

	/* Parse S */
	if (der[pos++] != 0x02) /* INTEGER tag */
		return -1;

	*s_len = der[pos++];
	/* Skip leading zero if present */
	if (der[pos] == 0x00 && *s_len > 1) {
		pos++;
		(*s_len)--;
	}
	memcpy(s, der + pos, *s_len);

	return 0;
}

/*
 * Sign hash with ECDSA (JWS format)
 *
 * NOTE: JWS signatures use R||S format (concatenated), not DER encoding
 */
int
lws_genecdsa_hash_sign_jws(struct lws_genec_ctx *ctx, const uint8_t *in,
			   enum lws_genhash_types hash_type, int keybits,
			   uint8_t *sig, size_t sig_len)
{
	CRYPT_MD_AlgId md_id;
	int32_t ret;
	size_t keybytes = (size_t)lws_gencrypto_bits_to_bytes(keybits);

	if (!ctx || !ctx->ctx[LDHS_OURS] || ctx->genec_alg != LEGENEC_ECDSA) {
		lwsl_err("%s: invalid parameters or not ECDSA context\n", __func__);
		return -1;
	}

	if (!ctx->has_private) {
		lwsl_err("%s: no private key for signing\n", __func__);
		return -1;
	}

	if (sig_len < keybytes * 2) {
		lwsl_err("%s: signature buffer too small (%zu < %zu)\n",
			 __func__, sig_len, keybytes * 2);
		return -1;
	}

	md_id = lws_gencrypto_openhitls_hash_to_MD_ID(hash_type);
	if (md_id == CRYPT_MD_MAX) {
		lwsl_err("%s: unsupported hash type\n", __func__);
		return -1;
	}

	/*
	 * Sign the hash - openHiTLS produces DER-encoded signatures
	 */
	uint8_t der_sig[256]; /* Temporary buffer for DER signature */
	uint32_t der_len = sizeof(der_sig);
	uint8_t r[128], s[128];
	size_t r_len = 0, s_len = 0;

	ret = CRYPT_EAL_PkeySignData((CRYPT_EAL_PkeyCtx *)ctx->ctx[LDHS_OURS],
				      in, (uint32_t)lws_genhash_size(hash_type),
				      der_sig, &der_len);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeySignData failed: 0x%x\n",
			 __func__, ret);
		return -1;
	}

	/*
	 * Convert DER-encoded signature to JWS R||S format:
	 * 1. Parse DER to extract R and S values
	 * 2. Pad R and S to keybytes length (left-pad with zeros)
	 * 3. Concatenate as R||S
	 */
	if (parse_der_sig(der_sig, der_len, r, &r_len, s, &s_len) != 0) {
		lwsl_err("%s: failed to parse DER signature\n", __func__);
		return -1;
	}

	/* Clear output buffer */
	memset(sig, 0, keybytes * 2);

	/* Copy R (right-aligned, left-padded with zeros if needed) */
	if (r_len > keybytes) {
		lwsl_err("%s: R length %zu exceeds keybytes %zu\n",
			 __func__, r_len, keybytes);
		return -1;
	}
	memcpy(sig + (keybytes - r_len), r, r_len);

	/* Copy S (right-aligned, left-padded with zeros if needed) */
	if (s_len > keybytes) {
		lwsl_err("%s: S length %zu exceeds keybytes %zu\n",
			 __func__, s_len, keybytes);
		return -1;
	}
	memcpy(sig + keybytes + (keybytes - s_len), s, s_len);

	return (int)(keybytes * 2);
}

/*
 * Encode R||S signature to DER format
 * DER format: 30 [total-len] 02 [r-len] [r-bytes] 02 [s-len] [s-bytes]
 */
static int
encode_der_sig(const uint8_t *r, size_t r_len, const uint8_t *s, size_t s_len,
	       uint8_t *der, size_t *der_len)
{
	size_t pos = 0;
	size_t r_needs_padding = (r[0] & 0x80) ? 1 : 0;
	size_t s_needs_padding = (s[0] & 0x80) ? 1 : 0;
	size_t r_encoded_len = r_len + r_needs_padding;
	size_t s_encoded_len = s_len + s_needs_padding;
	size_t total_len = 2 + r_encoded_len + 2 + s_encoded_len;

	if (*der_len < total_len + 2) {
		return -1; /* Buffer too small */
	}

	/* SEQUENCE tag */
	der[pos++] = 0x30;
	der[pos++] = (uint8_t)total_len;

	/* R INTEGER */
	der[pos++] = 0x02;
	der[pos++] = (uint8_t)r_encoded_len;
	if (r_needs_padding)
		der[pos++] = 0x00;
	memcpy(der + pos, r, r_len);
	pos += r_len;

	/* S INTEGER */
	der[pos++] = 0x02;
	der[pos++] = (uint8_t)s_encoded_len;
	if (s_needs_padding)
		der[pos++] = 0x00;
	memcpy(der + pos, s, s_len);
	pos += s_len;

	*der_len = pos;
	return 0;
}

/*
 * Verify ECDSA signature (JWS format)
 */
int
lws_genecdsa_hash_sig_verify_jws(struct lws_genec_ctx *ctx, const uint8_t *in,
				 enum lws_genhash_types hash_type, int keybits,
				 const uint8_t *sig, size_t sig_len)
{
	CRYPT_MD_AlgId md_id;
	int32_t ret;
	size_t keybytes = (size_t)lws_gencrypto_bits_to_bytes(keybits);

	if (!ctx || !ctx->ctx[LDHS_OURS] || ctx->genec_alg != LEGENEC_ECDSA) {
		lwsl_err("%s: invalid parameters or not ECDSA context\n", __func__);
		return -1;
	}

	if (sig_len != keybytes * 2) {
		lwsl_err("%s: invalid signature length (%zu != %zu)\n",
			 __func__, sig_len, keybytes * 2);
		return -1;
	}

	md_id = lws_gencrypto_openhitls_hash_to_MD_ID(hash_type);
	if (md_id == CRYPT_MD_MAX) {
		lwsl_err("%s: unsupported hash type\n", __func__);
		return -1;
	}

	/*
	 * Convert JWS R||S format to DER for openHiTLS
	 * JWS format: R||S (each component is keybytes long, zero-padded)
	 * Need to strip leading zeros and encode as DER
	 */
	uint8_t der_sig[256];
	size_t der_len = sizeof(der_sig);
	const uint8_t *r_ptr = sig;
	const uint8_t *s_ptr = sig + keybytes;
	size_t r_len = keybytes;
	size_t s_len = keybytes;

	/* Strip leading zeros from R */
	while (r_len > 1 && *r_ptr == 0x00) {
		r_ptr++;
		r_len--;
	}

	/* Strip leading zeros from S */
	while (s_len > 1 && *s_ptr == 0x00) {
		s_ptr++;
		s_len--;
	}

	/* Encode to DER */
	if (encode_der_sig(r_ptr, r_len, s_ptr, s_len, der_sig, &der_len) != 0) {
		lwsl_err("%s: failed to encode DER signature\n", __func__);
		return -1;
	}

	ret = CRYPT_EAL_PkeyVerifyData((CRYPT_EAL_PkeyCtx *)ctx->ctx[LDHS_OURS],
					in, (uint32_t)lws_genhash_size(hash_type),
					der_sig, (uint32_t)der_len);
	if (ret != CRYPT_SUCCESS) {
		lwsl_notice("%s: signature verification failed: 0x%x\n",
			    __func__, ret);
		return -1;
	}

	return 0;
}

/*
 * Compute ECDH shared secret
 */
int
lws_genecdh_compute_shared_secret(struct lws_genec_ctx *ctx, uint8_t *ss,
				  int *ss_len)
{
	uint32_t shareLen;
	int32_t ret;

	if (!ctx || ctx->genec_alg != LEGENEC_ECDH || !ss || !ss_len) {
		lwsl_err("%s: invalid parameters or not ECDH context\n", __func__);
		return -1;
	}

	if (!ctx->ctx[LDHS_OURS] || !ctx->ctx[LDHS_THEIRS]) {
		lwsl_err("%s: both our and their keys must be set\n", __func__);
		return -1;
	}

	shareLen = (uint32_t)*ss_len;

	/*
	 * Compute ECDH shared secret
	 * The result is the X coordinate of the shared point
	 */
	ret = CRYPT_EAL_PkeyComputeShareKey(
		(CRYPT_EAL_PkeyCtx *)ctx->ctx[LDHS_OURS],
		(CRYPT_EAL_PkeyCtx *)ctx->ctx[LDHS_THEIRS],
		ss, &shareLen);

	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyComputeShareKey failed: 0x%x\n",
			 __func__, ret);
		return -1;
	}

	*ss_len = (int)shareLen;
	return 0;
}

/*
 * Destroy EC context
 */
void
lws_genec_destroy(struct lws_genec_ctx *ctx)
{
	if (!ctx)
		return;

	if (ctx->ctx[LDHS_OURS]) {
		CRYPT_EAL_PkeyFreeCtx((CRYPT_EAL_PkeyCtx *)ctx->ctx[LDHS_OURS]);
		ctx->ctx[LDHS_OURS] = NULL;
	}

	if (ctx->ctx[LDHS_THEIRS]) {
		CRYPT_EAL_PkeyFreeCtx((CRYPT_EAL_PkeyCtx *)ctx->ctx[LDHS_THEIRS]);
		ctx->ctx[LDHS_THEIRS] = NULL;
	}

	ctx->has_private = 0;
}

/*
 * Destroy EC key elements
 */
void
lws_genec_destroy_elements(struct lws_gencrypto_keyelem *el)
{
	lws_gencrypto_destroy_elements(el, LWS_GENCRYPTO_EC_KEYEL_COUNT);
}
