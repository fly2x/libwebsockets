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
 * openHiTLS AES implementation
 */

#include "private-lib-core.h"
#include <hitls/crypto/crypt_eal_cipher.h>
#include <hitls/crypto/crypt_algid.h>
#include <hitls/crypto/crypt_errno.h>
#include <hitls/crypto/crypt_types.h>

/*
 * Map AES mode and key length to openHiTLS cipher algorithm
 */
static CRYPT_CIPHER_AlgId
lws_genaes_get_alg(enum enum_aes_modes mode, size_t keylen)
{
	switch (mode) {
	case LWS_GAESM_CBC:
		switch (keylen) {
		case 16: return CRYPT_CIPHER_AES128_CBC;
		case 24: return CRYPT_CIPHER_AES192_CBC;
		case 32: return CRYPT_CIPHER_AES256_CBC;
		default: return CRYPT_CIPHER_MAX;
		}
	case LWS_GAESM_CFB128:
		switch (keylen) {
		case 16: return CRYPT_CIPHER_AES128_CFB;
		case 24: return CRYPT_CIPHER_AES192_CFB;
		case 32: return CRYPT_CIPHER_AES256_CFB;
		default: return CRYPT_CIPHER_MAX;
		}
	case LWS_GAESM_CTR:
		switch (keylen) {
		case 16: return CRYPT_CIPHER_AES128_CTR;
		case 24: return CRYPT_CIPHER_AES192_CTR;
		case 32: return CRYPT_CIPHER_AES256_CTR;
		default: return CRYPT_CIPHER_MAX;
		}
	case LWS_GAESM_GCM:
		switch (keylen) {
		case 16: return CRYPT_CIPHER_AES128_GCM;
		case 24: return CRYPT_CIPHER_AES192_GCM;
		case 32: return CRYPT_CIPHER_AES256_GCM;
		default: return CRYPT_CIPHER_MAX;
		}
	case LWS_GAESM_ECB:
		switch (keylen) {
		case 16: return CRYPT_CIPHER_AES128_ECB;
		case 24: return CRYPT_CIPHER_AES192_ECB;
		case 32: return CRYPT_CIPHER_AES256_ECB;
		default: return CRYPT_CIPHER_MAX;
		}
	case LWS_GAESM_OFB:
		switch (keylen) {
		case 16: return CRYPT_CIPHER_AES128_OFB;
		case 24: return CRYPT_CIPHER_AES192_OFB;
		case 32: return CRYPT_CIPHER_AES256_OFB;
		default: return CRYPT_CIPHER_MAX;
		}
	default:
		return CRYPT_CIPHER_MAX;
	}
}

/*
 * Create AES context - stores parameters, delays cipher initialization
 * until first crypt call when IV is provided
 */
int
lws_genaes_create(struct lws_genaes_ctx *ctx, enum enum_aes_operation op,
		  enum enum_aes_modes mode, struct lws_gencrypto_keyelem *el,
		  enum enum_aes_padding padding, void *engine)
{
	CRYPT_CIPHER_AlgId alg;

	if (!ctx || !el || !el->buf || el->len == 0) {
		lwsl_err("%s: invalid parameters\n", __func__);
		return -1;
	}

	/* Get algorithm ID for this mode and key length */
	alg = lws_genaes_get_alg(mode, el->len);
	if (alg == CRYPT_CIPHER_MAX) {
		lwsl_err("%s: unsupported mode %d or key length %u\n",
			 __func__, mode, (unsigned)el->len);
		return -1;
	}

	memset(ctx, 0, sizeof(*ctx));

	/* Store parameters for later use */
	ctx->k = el;
	ctx->op = op;
	ctx->mode = mode;
	ctx->padding = padding;
	ctx->engine = engine;
	ctx->init = 0;
	ctx->underway = 0;

	/* Create cipher context - will be initialized in lws_genaes_crypt() */
	ctx->ctx = (void *)CRYPT_EAL_CipherNewCtx(alg);
	if (!ctx->ctx) {
		lwsl_err("%s: CRYPT_EAL_CipherNewCtx failed for alg %d\n",
			 __func__, alg);
		return -1;
	}

	return 0;
}

/*
 * Encrypt/decrypt data
 */
int
lws_genaes_crypt(struct lws_genaes_ctx *ctx, const uint8_t *in, size_t len,
		 uint8_t *out, uint8_t *iv_or_nonce_ctr_or_data_unit_16,
		 uint8_t *stream_block_16, size_t *nc_or_iv_off, int taglen)
{
	uint32_t outlen;
	int32_t ret;

	if (!ctx || !ctx->ctx || !ctx->k) {
		lwsl_err("%s: context not initialized\n", __func__);
		return -1;
	}

	if (!in || !out || len == 0) {
		lwsl_err("%s: invalid parameters\n", __func__);
		return -1;
	}

	/* Initialize cipher on first call */
	if (!ctx->init) {
		bool encrypt = (ctx->op == LWS_GAESO_ENC);
		uint8_t *iv = NULL;
		uint32_t ivlen = 0;

		/* Modes that require IV */
		if (ctx->mode != LWS_GAESM_ECB && iv_or_nonce_ctr_or_data_unit_16) {
			iv = iv_or_nonce_ctr_or_data_unit_16;
			/* Standard IV length for most modes */
			if (ctx->mode == LWS_GAESM_GCM && nc_or_iv_off)
				ivlen = (uint32_t)*nc_or_iv_off;
			else
				ivlen = 16;
		}

		ret = CRYPT_EAL_CipherInit((CRYPT_EAL_CipherCtx *)ctx->ctx,
					   ctx->k->buf, (uint32_t)ctx->k->len,
					   iv, ivlen, encrypt);
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: CRYPT_EAL_CipherInit failed: 0x%x\n",
				 __func__, ret);
			return -1;
		}

		/* Set padding mode for block ciphers (CBC, ECB) */
		if (ctx->mode == LWS_GAESM_CBC || ctx->mode == LWS_GAESM_ECB) {
			CRYPT_PaddingType pad_type = (ctx->padding == LWS_GAESP_WITH_PADDING) ?
						     CRYPT_PADDING_PKCS7 : CRYPT_PADDING_NONE;
			ret = CRYPT_EAL_CipherSetPadding((CRYPT_EAL_CipherCtx *)ctx->ctx, pad_type);
			if (ret != CRYPT_SUCCESS) {
				lwsl_err("%s: CRYPT_EAL_CipherSetPadding failed: 0x%x\n",
					 __func__, ret);
				return -1;
			}
		}

		/* For GCM mode, handle tag  */
		if (ctx->mode == LWS_GAESM_GCM) {
			/* Set tag length */
			if (taglen > 0) {
				uint32_t tlen = (uint32_t)taglen;
				ret = CRYPT_EAL_CipherCtrl((CRYPT_EAL_CipherCtx *)ctx->ctx,
							   CRYPT_CTRL_SET_TAGLEN,
							   &tlen, sizeof(tlen));
				if (ret != CRYPT_SUCCESS) {
					lwsl_err("%s: failed to set GCM tag length: 0x%x\n",
						 __func__, ret);
					return -1;
				}
				ctx->taglen = taglen;
			}
			/* For encryption, tag will be retrieved in destroy */
			/* For decryption, tag verification happens in Final */
			/* Note: openHiTLS verifies tag internally during CipherFinal */
			if (!encrypt && taglen > 0 && stream_block_16) {
				/* Store tag for later verification */
				memcpy(ctx->tag, stream_block_16, (size_t)taglen);
			}
		}

		ctx->init = 1;
	}

	/* For CBC/ECB modes with padding, we need to handle encryption/decryption
	 * completely here (including Final) to match mbedTLS behavior where
	 * the caller doesn't need to know about padded lengths.
	 */
	if ((ctx->mode == LWS_GAESM_CBC || ctx->mode == LWS_GAESM_ECB) &&
	    ctx->padding == LWS_GAESP_WITH_PADDING) {
		uint8_t temp_buf[4096]; /* Temporary buffer for padding handling */
		uint32_t update_len, final_len;
		uint32_t actual_input_len;

		if (ctx->op == LWS_GAESO_ENC) {
			/* Encryption: input is plaintext, output will include padding */
			actual_input_len = (uint32_t)len;
		} else {
			/* Decryption: calculate actual ciphertext length (must be block-aligned) */
			actual_input_len = (((uint32_t)len + 15) / 16) * 16;
		}

		/* CipherUpdate */
		update_len = sizeof(temp_buf);
		ret = CRYPT_EAL_CipherUpdate((CRYPT_EAL_CipherCtx *)ctx->ctx,
					     in, actual_input_len, temp_buf, &update_len);
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: CipherUpdate failed: 0x%x\n", __func__, ret);
			return -1;
		}

		/* CipherFinal to handle padding */
		final_len = sizeof(temp_buf) - update_len;
		ret = CRYPT_EAL_CipherFinal((CRYPT_EAL_CipherCtx *)ctx->ctx,
					    temp_buf + update_len, &final_len);
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: CipherFinal failed: 0x%x\n", __func__, ret);
			return -1;
		}

		/* Copy result to output buffer */
		memcpy(out, temp_buf, update_len + final_len);

		/* Mark that Final has been called */
		ctx->underway = 2; /* 2 = completed with Final */

		return 0;
	}

	/* For GCM mode, handle all operations here (no Final needed) */
	if (ctx->mode == LWS_GAESM_GCM) {
		outlen = (uint32_t)(len + 32);

		ret = CRYPT_EAL_CipherUpdate((CRYPT_EAL_CipherCtx *)ctx->ctx,
					     in, (uint32_t)len, out, &outlen);
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: GCM CipherUpdate failed: 0x%x\n",
				 __func__, ret);
			return -1;
		}

		/* For GCM, mark as completed (no Final needed) */
		ctx->underway = 2; /* 2 = completed, no Final needed */

		return 0;
	}

	/* For other modes (CTR, etc.), just do Update */
	outlen = (uint32_t)(len + 32);

	ret = CRYPT_EAL_CipherUpdate((CRYPT_EAL_CipherCtx *)ctx->ctx,
				     in, (uint32_t)len, out, &outlen);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_CipherUpdate failed: 0x%x\n",
			 __func__, ret);
		return -1;
	}

	ctx->underway = 1; /* 1 = Update called, Final still needed */

	return 0;
}

/*
 * Finalize and destroy AES context
 */
int
lws_genaes_destroy(struct lws_genaes_ctx *ctx, unsigned char *tag, size_t tlen)
{
	uint8_t final_block[32];
	uint32_t outlen;
	int32_t ret = 0;

	if (!ctx)
		return -1;

	if (!ctx->ctx)
		return 0;

	/* Finalize cipher if data was processed and Final hasn't been called yet
	 * underway == 1: Update called, need Final (for GCM, CTR, etc.)
	 * underway == 2: Final already called in crypt (for CBC with padding)
	 */
	if (ctx->underway == 1) {
		/* outLen must be set to buffer size (input), returns actual size (output) */
		/* For padding modes: outLen >= blockSize (16 for AES) */
		outlen = sizeof(final_block);

		ret = CRYPT_EAL_CipherFinal((CRYPT_EAL_CipherCtx *)ctx->ctx,
					    final_block, &outlen);
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: CRYPT_EAL_CipherFinal failed: 0x%x\n",
				 __func__, ret);
			ret = -1;
		}

		/* Get GCM tag if requested */
		if (tag && tlen > 0 && ctx->mode == LWS_GAESM_GCM &&
		    ctx->op == LWS_GAESO_ENC) {
			size_t copy_len = tlen < sizeof(ctx->tag) ?
					  tlen : sizeof(ctx->tag);
			ret = CRYPT_EAL_CipherCtrl((CRYPT_EAL_CipherCtx *)ctx->ctx,
						   CRYPT_CTRL_GET_TAG,
						   ctx->tag, (uint32_t)copy_len);
			if (ret == CRYPT_SUCCESS) {
				memcpy(tag, ctx->tag, copy_len);
				ret = 0;
			} else {
				lwsl_err("%s: failed to get GCM tag: 0x%x\n",
					 __func__, ret);
				ret = -1;
			}
		}
	}

	/* For GCM encryption that was completed in crypt (underway==2),
	 * we still need to extract the tag here in destroy
	 */
	if (ctx->underway == 2 && tag && tlen > 0 && ctx->mode == LWS_GAESM_GCM &&
	    ctx->op == LWS_GAESO_ENC) {
		ret = CRYPT_EAL_CipherCtrl((CRYPT_EAL_CipherCtx *)ctx->ctx,
					   CRYPT_CTRL_GET_TAG,
					   tag, (uint32_t)tlen);
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: failed to get GCM tag (underway=2): 0x%x\n",
				 __func__, ret);
			ret = -1;
		} else {
			ret = 0;
		}
	}

	/* Free context */
	CRYPT_EAL_CipherFreeCtx((CRYPT_EAL_CipherCtx *)ctx->ctx);
	ctx->ctx = NULL;
	ctx->init = 0;
	ctx->underway = 0;

	return ret;
}
