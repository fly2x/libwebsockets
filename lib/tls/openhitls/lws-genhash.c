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
 * openHiTLS hash and HMAC implementation
 */

#include "private-lib-core.h"
#include <hitls/crypto/crypt_eal_md.h>
#include <hitls/crypto/crypt_eal_mac.h>
#include <hitls/crypto/crypt_algid.h>
#include <hitls/crypto/crypt_errno.h>

/*
 * Initialize hash context
 */
int
lws_genhash_init(struct lws_genhash_ctx *ctx, enum lws_genhash_types type)
{
	CRYPT_MD_AlgId alg;

	ctx->type = (uint8_t)type;

	/* Map libwebsockets hash types to openHiTLS algorithm IDs */
	switch (type) {
	case LWS_GENHASH_TYPE_SHA1:
		alg = CRYPT_MD_SHA1;
		break;
	case LWS_GENHASH_TYPE_SHA256:
		alg = CRYPT_MD_SHA256;
		break;
	case LWS_GENHASH_TYPE_SHA384:
		alg = CRYPT_MD_SHA384;
		break;
	case LWS_GENHASH_TYPE_SHA512:
		alg = CRYPT_MD_SHA512;
		break;
	default:
		lwsl_err("%s: unsupported hash type: %d\n", __func__, type);
		return -1;
	}

	/* Create hash context */
	ctx->mdctx = (void *)CRYPT_EAL_MdNewCtx(alg);
	if (!ctx->mdctx) {
		lwsl_err("%s: CRYPT_EAL_MdNewCtx failed\n", __func__);
		return -1;
	}

	/* Initialize hash */
	if (CRYPT_EAL_MdInit((CRYPT_EAL_MdCTX *)ctx->mdctx) != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_MdInit failed\n", __func__);
		CRYPT_EAL_MdFreeCtx((CRYPT_EAL_MdCTX *)ctx->mdctx);
		ctx->mdctx = NULL;
		return -1;
	}

	return 0;
}

/*
 * Update hash with data
 */
int
lws_genhash_update(struct lws_genhash_ctx *ctx, const void *in, size_t len)
{
	if (!ctx->mdctx) {
		lwsl_err("%s: hash not initialized\n", __func__);
		return -1;
	}

	if (CRYPT_EAL_MdUpdate((CRYPT_EAL_MdCTX *)ctx->mdctx,
			       (const uint8_t *)in,
			       (uint32_t)len) != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_MdUpdate failed\n", __func__);
		return -1;
	}

	return 0;
}

/*
 * Finalize hash and destroy context
 */
int
lws_genhash_destroy(struct lws_genhash_ctx *ctx, void *result)
{
	uint32_t len;
	int ret = 0;

	if (!ctx->mdctx) {
		lwsl_err("%s: hash not initialized\n", __func__);
		return -1;
	}

	if (result) {
		/* Finalize and get result */
		if (CRYPT_EAL_MdFinal((CRYPT_EAL_MdCTX *)ctx->mdctx,
				      (uint8_t *)result, &len) != CRYPT_SUCCESS) {
			lwsl_err("%s: CRYPT_EAL_MdFinal failed\n", __func__);
			ret = -1;
		}
	}

	/* Free context */
	CRYPT_EAL_MdFreeCtx((CRYPT_EAL_MdCTX *)ctx->mdctx);
	ctx->mdctx = NULL;

	return ret;
}

/*
 * Initialize HMAC context
 */
int
lws_genhmac_init(struct lws_genhmac_ctx *ctx, enum lws_genhmac_types type,
		 const uint8_t *key, size_t key_len)
{
	CRYPT_MAC_AlgId alg;
	int32_t ret;

	if (!ctx || !key) {
		lwsl_err("%s: invalid parameters\n", __func__);
		return -1;
	}

	ctx->type = (uint8_t)type;

	/* Map libwebsockets HMAC types to openHiTLS algorithm IDs */
	switch (type) {
	case LWS_GENHMAC_TYPE_SHA256:
		alg = CRYPT_MAC_HMAC_SHA256;
		break;
	case LWS_GENHMAC_TYPE_SHA384:
		alg = CRYPT_MAC_HMAC_SHA384;
		break;
	case LWS_GENHMAC_TYPE_SHA512:
		alg = CRYPT_MAC_HMAC_SHA512;
		break;
	default:
		lwsl_err("%s: unsupported HMAC type: %d\n", __func__, type);
		return -1;
	}

	/* Create MAC context */
	ctx->macctx = (void *)CRYPT_EAL_MacNewCtx(alg);
	if (!ctx->macctx) {
		lwsl_err("%s: CRYPT_EAL_MacNewCtx failed\n", __func__);
		return -1;
	}

	/* Initialize HMAC with key */
	ret = CRYPT_EAL_MacInit((CRYPT_EAL_MacCtx *)ctx->macctx,
				key, (uint32_t)key_len);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_MacInit failed: 0x%x\n", __func__, ret);
		CRYPT_EAL_MacFreeCtx((CRYPT_EAL_MacCtx *)ctx->macctx);
		ctx->macctx = NULL;
		return -1;
	}

	return 0;
}

/*
 * Update HMAC with data
 */
int
lws_genhmac_update(struct lws_genhmac_ctx *ctx, const void *in, size_t len)
{
	int32_t ret;

	if (!ctx || !ctx->macctx) {
		lwsl_err("%s: HMAC not initialized\n", __func__);
		return -1;
	}

	if (!in && len != 0) {
		lwsl_err("%s: invalid parameters\n", __func__);
		return -1;
	}

	ret = CRYPT_EAL_MacUpdate((CRYPT_EAL_MacCtx *)ctx->macctx,
				  (const uint8_t *)in, (uint32_t)len);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_MacUpdate failed: 0x%x\n", __func__, ret);
		return -1;
	}

	return 0;
}

/*
 * Finalize HMAC and destroy context
 */
int
lws_genhmac_destroy(struct lws_genhmac_ctx *ctx, void *result)
{
	uint32_t len;
	int32_t ret;
	int retval = 0;

	if (!ctx || !ctx->macctx) {
		lwsl_err("%s: HMAC not initialized\n", __func__);
		return -1;
	}

	if (result) {
		/* Finalize and get result */
		len = (uint32_t)lws_genhmac_size(ctx->type);
		ret = CRYPT_EAL_MacFinal((CRYPT_EAL_MacCtx *)ctx->macctx,
					 (uint8_t *)result, &len);
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: CRYPT_EAL_MacFinal failed: 0x%x\n",
				 __func__, ret);
			retval = -1;
		}
	}

	/* Free context */
	CRYPT_EAL_MacFreeCtx((CRYPT_EAL_MacCtx *)ctx->macctx);
	ctx->macctx = NULL;

	return retval;
}
