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
 * openHiTLS X.509 certificate operations
 */

#include "private-lib-core.h"
#include "private-lib-tls-openhitls.h"

#include <hitls/pki/hitls_pki_cert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/*
 * Helper function to read file into buffer
 */
int
lws_read_file_to_buffer(const char *path, uint8_t **buf, size_t *len)
{
	struct stat st;
	int fd;
	ssize_t n;
	uint8_t *data;

	if (stat(path, &st) < 0) {
		lwsl_err("%s: stat failed for %s: %s\n",
			 __func__, path, strerror(errno));
		return -1;
	}

	data = lws_malloc((size_t)st.st_size + 1, "cert-file");
	if (!data) {
		lwsl_err("%s: malloc failed\n", __func__);
		return -1;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		lwsl_err("%s: open failed for %s: %s\n",
			 __func__, path, strerror(errno));
		lws_free(data);
		return -1;
	}

	n = read(fd, data, (size_t)st.st_size);
	close(fd);

	if (n != st.st_size) {
		lwsl_err("%s: read failed for %s\n", __func__, path);
		lws_free(data);
		return -1;
	}

	data[st.st_size] = '\0';
	*buf = data;
	*len = (size_t)st.st_size;

	return 0;
}

/*
 * Load certificate and private key from files
 */
int
lws_openhitls_load_cert_from_file(HITLS_Config *config,
				   const char *cert_path,
				   const char *key_path)
{
	int32_t ret;

	if (!config || !cert_path) {
		lwsl_err("%s: invalid parameters\n", __func__);
		return -1;
	}

	lwsl_info("%s: loading certificate from %s\n", __func__, cert_path);

	/* Load certificate file */
	ret = HITLS_CFG_LoadCertFile(config, cert_path, TLS_PARSE_FORMAT_PEM);
	if (ret != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CFG_LoadCertFile failed: 0x%x\n",
			 __func__, ret);
		return -1;
	}

	lwsl_info("%s: certificate loaded successfully\n", __func__);

	/* Load private key file if provided */
	if (key_path) {
		lwsl_info("%s: loading private key from %s\n", __func__, key_path);

		ret = HITLS_CFG_LoadKeyFile(config, key_path, TLS_PARSE_FORMAT_PEM);
		if (ret != HITLS_SUCCESS) {
			lwsl_err("%s: HITLS_CFG_LoadKeyFile failed: 0x%x\n",
				 __func__, ret);
			return -1;
		}

		lwsl_info("%s: private key loaded successfully\n", __func__);
	}

	return 0;
}

/*
 * Load certificate and private key from memory
 */
int
lws_openhitls_load_cert_from_mem(HITLS_Config *config,
				  const uint8_t *cert_data,
				  uint32_t cert_len,
				  const uint8_t *key_data,
				  uint32_t key_len)
{
	int32_t ret;

	if (!config || !cert_data || cert_len == 0) {
		lwsl_err("%s: invalid parameters\n", __func__);
		return -1;
	}

	lwsl_info("%s: loading certificate from memory (%u bytes)\n",
		  __func__, cert_len);

	/* Load certificate from buffer */
	ret = HITLS_CFG_LoadCertBuffer(config, cert_data, cert_len,
				       TLS_PARSE_FORMAT_PEM);
	if (ret != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CFG_LoadCertBuffer failed: 0x%x\n",
			 __func__, ret);
		return -1;
	}

	/* Load private key from buffer if provided */
	if (key_data && key_len > 0) {
		lwsl_info("%s: loading private key from memory (%u bytes)\n",
			  __func__, key_len);

		ret = HITLS_CFG_LoadKeyBuffer(config, key_data, key_len,
					      TLS_PARSE_FORMAT_PEM);
		if (ret != HITLS_SUCCESS) {
			lwsl_err("%s: HITLS_CFG_LoadKeyBuffer failed: 0x%x\n",
				 __func__, ret);
			return -1;
		}
	}

	lwsl_info("%s: certificate loaded from memory successfully\n", __func__);

	return 0;
}

/*
 * Load CA certificates from file
 * Following the pattern from openHiTLS demo: client.c
 */
int
lws_openhitls_load_ca_from_file(HITLS_Config *config, const char *ca_path)
{
	HITLS_X509_Cert *cert = NULL;
	int32_t ret;

	if (!config || !ca_path) {
		lwsl_err("%s: invalid parameters\n", __func__);
		return -1;
	}

	lwsl_info("%s: loading CA certificates from %s\n", __func__, ca_path);

	/* Parse CA certificate file directly - matches demo pattern */
	ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, ca_path, &cert);
	if (ret != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_X509_CertParseFile failed: 0x%x\n",
			 __func__, ret);
		return -1;
	}

	/* Add certificate to verify store
	 * TLS_CERT_STORE_TYPE_DEFAULT for CA certs (as in demo)
	 * Set isClone=true to let openHiTLS manage the lifetime
	 */
	ret = HITLS_CFG_AddCertToStore(config, (HITLS_CERT_X509 *)cert,
				       TLS_CERT_STORE_TYPE_DEFAULT, true);
	if (ret != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CFG_AddCertToStore failed: 0x%x\n",
			 __func__, ret);
		HITLS_X509_CertFree(cert);
		return -1;
	}

	/* Free the cert after adding (since we used isClone=true) */
	HITLS_X509_CertFree(cert);

	lwsl_info("%s: CA certificates loaded successfully\n", __func__);

	return 0;
}

/*
 * Load server certificates
 */
int
lws_tls_server_certs_load(struct lws_vhost *vhost, struct lws *wsi,
			   const char *cert, const char *private_key,
			   const char *mem_cert, size_t len_mem_cert,
			   const char *mem_privkey, size_t mem_privkey_len)
{
	HITLS_Config *config = (HITLS_Config *)vhost->tls.ssl_ctx;
	int ret;

	if (!config) {
		lwsl_err("%s: no SSL config\n", __func__);
		return -1;
	}

	/* Prefer memory certificates if provided */
	if (mem_cert && len_mem_cert > 0) {
		ret = lws_openhitls_load_cert_from_mem(config,
						       (const uint8_t *)mem_cert,
						       (uint32_t)len_mem_cert,
						       (const uint8_t *)mem_privkey,
						       (uint32_t)mem_privkey_len);
		if (ret < 0) {
			lwsl_err("%s: failed to load certificate from memory\n",
				 __func__);
			return -1;
		}
	} else if (cert) {
		/* Load from files */
		ret = lws_openhitls_load_cert_from_file(config, cert,
							 private_key);
		if (ret < 0) {
			lwsl_err("%s: failed to load certificate from file\n",
				 __func__);
			return -1;
		}
	}

	return 0;
}

/*
 * Get certificate information
 */
int
lws_tls_vhost_cert_info(struct lws_vhost *vhost, enum lws_tls_cert_info type,
			union lws_tls_cert_info_results *buf, size_t len)
{
	/* TODO: Implement certificate info extraction */
	lwsl_debug("%s: not yet implemented\n", __func__);
	return -1;
}
