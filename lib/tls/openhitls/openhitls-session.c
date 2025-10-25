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
 * openHiTLS session management
 */

#include "private-lib-core.h"
#include "private-lib-tls-openhitls.h"

/*
 * Enable session reuse
 */
void
lws_tls_reuse_session(struct lws *wsi)
{
	if (!wsi->tls.ssl) {
		lwsl_warn("%s: no SSL context\n", __func__);
		return;
	}

	/* Get saved session from wsi user context if available */
	/* TODO: Implement session storage and retrieval mechanism */

	lwsl_debug("%s: session reuse not yet fully implemented\n", __func__);
}

/*
 * Configure session cache
 */
void
lws_tls_session_cache(struct lws_vhost *vh, uint32_t ttl)
{
	HITLS_Config *config = (HITLS_Config *)vh->tls.ssl_ctx;
	int32_t ret;

	if (!config) {
		lwsl_warn("%s: no SSL config\n", __func__);
		return;
	}

	lwsl_info("%s: configuring session cache with TTL: %u\n",
		  __func__, ttl);

	/* Set session cache mode */
	ret = HITLS_CFG_SetSessionCacheMode(config,
					    HITLS_SESS_CACHE_SERVER |
					    HITLS_SESS_CACHE_CLIENT);
	if (ret != HITLS_SUCCESS) {
		lwsl_warn("%s: HITLS_CFG_SetSessionCacheMode failed: 0x%x\n",
			  __func__, ret);
		return;
	}

	/* Set session timeout if specified */
	if (ttl > 0) {
		ret = HITLS_CFG_SetSessionTimeout(config, ttl);
		if (ret != HITLS_SUCCESS) {
			lwsl_warn("%s: HITLS_CFG_SetSessionTimeout failed: 0x%x\n",
				  __func__, ret);
			return;
		}
	}

	lwsl_info("%s: session cache configured successfully\n", __func__);
}

/*
 * Destroy vhost session cache
 */
void
lws_tls_session_vh_destroy(struct lws_vhost *vh)
{
	/* openHiTLS manages session cache internally */
	lwsl_info("%s: vhost session cleanup\n", __func__);
}

/*
 * ALPN support - convert from comma-separated string to length-prefixed format
 * Input format: "http/1.1,h2"
 * Output format: "\x08http/1.1\x02h2" (length-prefixed wire format)
 */
int
lws_openhitls_set_alpn(HITLS_Config *config, const char *alpn)
{
	uint8_t alpn_buf[256];
	uint8_t *p = alpn_buf;
	const char *start, *end;
	size_t len, total_len = 0;
	int32_t ret;

	if (!config || !alpn) {
		lwsl_err("%s: invalid parameters\n", __func__);
		return -1;
	}

	lwsl_info("%s: setting ALPN: %s\n", __func__, alpn);

	/* Convert comma-separated string to length-prefixed format */
	start = alpn;
	while (*start) {
		/* Skip whitespace */
		while (*start == ' ' || *start == '\t')
			start++;

		if (!*start)
			break;

		/* Find end of this protocol name */
		end = start;
		while (*end && *end != ',' && *end != ' ' && *end != '\t')
			end++;

		len = (size_t)(end - start);
		if (len == 0 || len > 255) {
			lwsl_err("%s: invalid protocol length: %zu\n", __func__, len);
			return -1;
		}

		if (total_len + len + 1 > sizeof(alpn_buf)) {
			lwsl_err("%s: ALPN buffer too small\n", __func__);
			return -1;
		}

		/* Write length prefix and protocol name */
		*p++ = (uint8_t)len;
		memcpy(p, start, len);
		p += len;
		total_len += len + 1;

		/* Move to next protocol */
		start = end;
		if (*start == ',')
			start++;
	}

	if (total_len == 0) {
		lwsl_warn("%s: empty ALPN list\n", __func__);
		return 0;
	}

	/* Set ALPN protocols using openHiTLS API */
	ret = HITLS_CFG_SetAlpnProtos(config, alpn_buf, (uint32_t)total_len);
	if (ret != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CFG_SetAlpnProtos failed: 0x%x\n",
			 __func__, ret);
		return -1;
	}

	lwsl_info("%s: ALPN set successfully (%zu bytes)\n", __func__, total_len);
	return 0;
}

/*
 * Get negotiated ALPN protocol
 */
int
lws_openhitls_get_alpn(HITLS_Ctx *ctx, const uint8_t **data, uint32_t *len)
{
	int32_t ret;

	if (!ctx || !data || !len) {
		lwsl_err("%s: invalid parameters\n", __func__);
		return -1;
	}

	/* Get selected ALPN protocol using openHiTLS API */
	ret = HITLS_GetSelectedAlpnProto(ctx, (uint8_t **)data, len);
	if (ret != HITLS_SUCCESS) {
		lwsl_debug("%s: no ALPN negotiated (0x%x)\n", __func__, ret);
		*data = NULL;
		*len = 0;
		return -1;
	}

	if (*len == 0 || *data == NULL) {
		lwsl_debug("%s: ALPN returned empty\n", __func__);
		return -1;
	}

	lwsl_info("%s: ALPN negotiated: %.*s (%u bytes)\n", __func__,
		  (int)*len, *data, *len);

	return 0;
}

/*
 * Error string helper
 */
const char *
lws_openhitls_error_string(int32_t err)
{
	static char buf[32];
	lws_snprintf(buf, sizeof(buf), "openHiTLS error: 0x%x", err);
	return buf;
}
