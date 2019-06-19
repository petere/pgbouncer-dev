#include "bouncer.h"

#include <openssl/err.h>
#include <openssl/ocsp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>


//#ifdef USE_TLS

/* tls_internal.h */

static int tls_config_set_errorx(struct tls_config *cfg, const char *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)))
    __attribute__((__nonnull__ (2)));

static int tls_set_errorx(struct tls *ctx, const char *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)))
    __attribute__((__nonnull__ (2)));

static int tls_ssl_error(struct tls *ctx, SSL *ssl_conn, int ssl_ret,
    const char *prefix);

static int tls_configure_server(struct tls *ctx);
static int tls_handshake_client(struct tls *ctx);
static int tls_handshake_server(struct tls *ctx);

/* tls_compat.c */

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)

#define USE_LIBSSL_OLD

#define NID_kx_ecdhe (-90)
#define NID_kx_dhe (-91)
#define SSL_CIPHER_get_kx_nid(ciph) ( 0 )
#define ASN1_STRING_get0_data(x) ((const unsigned char*)ASN1_STRING_data(x))

#ifndef OPENSSL_VERSION
#define OPENSSL_VERSION SSLEAY_VERSION
#define OpenSSL_version(x) SSLeay_version(x)
#endif

#endif

#ifndef SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE
#undef SSLerr
#undef X509err
#endif

#ifndef SSLerr
#define SSLerr(a,b) do {} while (0)
#define X509err(a,b) do {} while (0)
#endif

#ifndef SSL_CTX_set_dh_auto
#define DH_CLEANUP

/*
 * SKIP primes, used by OpenSSL and PostgreSQL.
 *
 * https://tools.ietf.org/html/draft-ietf-ipsec-skip-06
 */

static const char file_dh1024[] =
"-----BEGIN DH PARAMETERS-----\n"
"MIGHAoGBAPSI/VhOSdvNILSd5JEHNmszbDgNRR0PfIizHHxbLY7288kjwEPwpVsY\n"
"jY67VYy4XTjTNP18F1dDox0YbN4zISy1Kv884bEpQBgRjXyEpwpy1obEAxnIByl6\n"
"ypUM2Zafq9AKUJsCRtMIPWakXUGfnHy9iUsiGSa6q6Jew1XpL3jHAgEC\n"
"-----END DH PARAMETERS-----\n";

static const char file_dh2048[] =
"-----BEGIN DH PARAMETERS-----\n"
"MIIBCAKCAQEA9kJXtwh/CBdyorrWqULzBej5UxE5T7bxbrlLOCDaAadWoxTpj0BV\n"
"89AHxstDqZSt90xkhkn4DIO9ZekX1KHTUPj1WV/cdlJPPT2N286Z4VeSWc39uK50\n"
"T8X8dryDxUcwYc58yWb/Ffm7/ZFexwGq01uejaClcjrUGvC/RgBYK+X0iP1YTknb\n"
"zSC0neSRBzZrM2w4DUUdD3yIsxx8Wy2O9vPJI8BD8KVbGI2Ou1WMuF040zT9fBdX\n"
"Q6MdGGzeMyEstSr/POGxKUAYEY18hKcKctaGxAMZyAcpesqVDNmWn6vQClCbAkbT\n"
"CD1mpF1Bn5x8vYlLIhkmuquiXsNV6TILOwIBAg==\n"
"-----END DH PARAMETERS-----\n";

static const char file_dh4096[] =
"-----BEGIN DH PARAMETERS-----\n"
"MIICCAKCAgEA+hRyUsFN4VpJ1O8JLcCo/VWr19k3BCgJ4uk+d+KhehjdRqNDNyOQ\n"
"l/MOyQNQfWXPeGKmOmIig6Ev/nm6Nf9Z2B1h3R4hExf+zTiHnvVPeRBhjdQi81rt\n"
"Xeoh6TNrSBIKIHfUJWBh3va0TxxjQIs6IZOLeVNRLMqzeylWqMf49HsIXqbcokUS\n"
"Vt1BkvLdW48j8PPv5DsKRN3tloTxqDJGo9tKvj1Fuk74A+Xda1kNhB7KFlqMyN98\n"
"VETEJ6c7KpfOo30mnK30wqw3S8OtaIR/maYX72tGOno2ehFDkq3pnPtEbD2CScxc\n"
"alJC+EL7RPk5c/tgeTvCngvc1KZn92Y//EI7G9tPZtylj2b56sHtMftIoYJ9+ODM\n"
"sccD5Piz/rejE3Ome8EOOceUSCYAhXn8b3qvxVI1ddd1pED6FHRhFvLrZxFvBEM9\n"
"ERRMp5QqOaHJkM+Dxv8Cj6MqrCbfC4u+ZErxodzuusgDgvZiLF22uxMZbobFWyte\n"
"OvOzKGtwcTqO/1wV5gKkzu1ZVswVUQd5Gg8lJicwqRWyyNRczDDoG9jVDxmogKTH\n"
"AaqLulO7R8Ifa1SwF2DteSGVtgWEN8gDpN3RBmmPTDngyF2DHb5qmpnznwtFKdTL\n"
"KWbuHn491xNO25CQWMtem80uKw+pTnisBRF/454n1Jnhub144YRBoN8CAQI=\n"
"-----END DH PARAMETERS-----\n";


static DH *dh1024, *dh2048, *dh4096;

static DH *load_dh_buffer(struct tls *ctx, DH **dhp, const char *buf)
{
	BIO *bio;
	DH *dh = *dhp;
	if (dh == NULL) {
		bio = BIO_new_mem_buf((char *)buf, strlen(buf));
		if (bio) {
			dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
			BIO_free(bio);
		}
		*dhp = dh;
	}
	if (ctx)
		ctx->used_dh_bits = DH_size(dh) * 8;
	return dh;
}

static DH *dh_auto_cb(SSL *s, int is_export, int keylength)
{
	EVP_PKEY *pk;
	int bits;
	struct tls *ctx = SSL_get_app_data(s);

	pk = SSL_get_privatekey(s);
	if (!pk)
		return load_dh_buffer(ctx, &dh2048, file_dh2048);

	bits = EVP_PKEY_bits(pk);
	if (bits >= 3072)
		return load_dh_buffer(ctx, &dh4096, file_dh4096);
	if (bits >= 1536)
		return load_dh_buffer(ctx, &dh2048, file_dh2048);
	return load_dh_buffer(ctx, &dh1024, file_dh1024);
}

static DH *dh_legacy_cb(SSL *s, int is_export, int keylength)
{
	struct tls *ctx = SSL_get_app_data(s);
	return load_dh_buffer(ctx, &dh1024, file_dh1024);
}

long SSL_CTX_set_dh_auto(SSL_CTX *ctx, int onoff)
{
	if (onoff == 0)
		return 1;
	if (onoff == 2) {
		SSL_CTX_set_tmp_dh_callback(ctx, dh_legacy_cb);
	} else {
		SSL_CTX_set_tmp_dh_callback(ctx, dh_auto_cb);
	}
	SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);
	return 1;
}

#endif

//#ifndef HAVE_SSL_CTX_USE_CERTIFICATE_CHAIN_MEM

/*
 * Load certs for public key from memory.
 */

static int
SSL_CTX_use_certificate_chain_mem(SSL_CTX *ctx, void *data, int data_len)
{
	pem_password_cb *psw_fn = NULL;
	void *psw_arg = NULL;
	X509 *cert;
	BIO *bio = NULL;
	int ok;

#ifdef USE_LIBSSL_OLD
	psw_fn = ctx->default_passwd_callback;
	psw_arg = ctx->default_passwd_callback_userdata;
#endif

	ERR_clear_error();

	/* Read from memory */
	bio = BIO_new_mem_buf(data, data_len);
	if (!bio) {
		SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE, ERR_R_BUF_LIB);
		goto failed;
	}

	/* Load primary cert */
	cert = PEM_read_bio_X509_AUX(bio, NULL, psw_fn, psw_arg);
	if (!cert) {
		SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE, ERR_R_PEM_LIB);
		goto failed;
	}

	/* Increments refcount */
	ok = SSL_CTX_use_certificate(ctx, cert);
	X509_free(cert);
	if (!ok || ERR_peek_error())
		goto failed;

	/* Load extra certs */
	ok = SSL_CTX_clear_extra_chain_certs(ctx);
	while (ok) {
		cert = PEM_read_bio_X509(bio, NULL, psw_fn, psw_arg);
		if (!cert) {
			/* Is it EOF? */
			unsigned long err = ERR_peek_last_error();
			if (ERR_GET_LIB(err) != ERR_LIB_PEM)
				break;
			if (ERR_GET_REASON(err) != PEM_R_NO_START_LINE)
				break;

			/* On EOF do successful exit */
			BIO_free(bio);
			ERR_clear_error();
			return 1;
		}
		/* Does not increment refcount */
		ok = SSL_CTX_add_extra_chain_cert(ctx, cert);
		if (!ok)
			X509_free(cert);
	}
 failed:
	if (bio)
		BIO_free(bio);
	return 0;
}

//#endif

//#ifndef HAVE_SSL_CTX_LOAD_VERIFY_MEM

/*
 * Load CA certs for verification from memory.
 */

static int
SSL_CTX_load_verify_mem(SSL_CTX *ctx, void *data, int data_len)
{
	STACK_OF(X509_INFO) *stack = NULL;
	X509_STORE *store;
	X509_INFO *info;
	int nstack, i, ret = 0, got = 0;
	BIO *bio;

	/* Read from memory */
	bio = BIO_new_mem_buf(data, data_len);
	if (!bio)
		goto failed;

	/* Parse X509_INFO records */
	stack = PEM_X509_INFO_read_bio(bio, NULL, NULL, NULL);
	if (!stack)
		goto failed;

	/* Loop over stack, add certs and revocation records to store */
	store = SSL_CTX_get_cert_store(ctx);
	nstack = sk_X509_INFO_num(stack);
	for (i = 0; i < nstack; i++) {
		info = sk_X509_INFO_value(stack, i);
		if (info->x509 && !X509_STORE_add_cert(store, info->x509))
			goto failed;
		if (info->crl && !X509_STORE_add_crl(store, info->crl))
			goto failed;
		if (info->x509 || info->crl)
			got = 1;
	}
	ret = got;
 failed:
	if (bio)
		BIO_free(bio);
	if (stack)
		sk_X509_INFO_pop_free(stack, X509_INFO_free);
	if (!ret)
		X509err(X509_F_X509_LOAD_CERT_CRL_FILE, ERR_R_PEM_LIB);
	return ret;
}

//#endif

//#ifndef HAVE_ASN1_TIME_PARSE

static int
parse2num(const char **str_p, int min, int max)
{
	const char *s = *str_p;
	if (s && s[0] >= '0' && s[0] <= '9' && s[1] >= '0' && s[1] <= '9') {
		int val = (s[0] - '0') * 10 + (s[1] - '0');
		if (val >= min && val <= max) {
			*str_p += 2;
			return val;
		}
	}
	*str_p = NULL;
	return 0;
}

static int
asn1_time_parse(const char *src, size_t len, struct tm *tm, int mode)
{
	char buf[16];
	const char *s = buf;
	int utctime;
	int year;

	memset(tm, 0, sizeof *tm);

	if (mode != 0)
		return -1;

	/*
	 * gentime: YYYYMMDDHHMMSSZ
	 * utctime: YYMMDDHHMM(SS)(Z)
	 */
	if (len == 15) {
		utctime = 0;
	} else if (len > 8 && len < 15) {
		utctime = 1;
	} else {
		return -1;
	}
	memcpy(buf, src, len);
	buf[len] = '\0';

	year = parse2num(&s, 0, 99);
	if (utctime) {
		if (year < 50)
			year = 2000 + year;
		else
			year = 1900 + year;
	} else {
		year = year*100 + parse2num(&s, 0, 99);
	}
	tm->tm_year = year - 1900;
	tm->tm_mon = parse2num(&s, 1, 12) - 1;
	tm->tm_mday = parse2num(&s, 1, 31);
	tm->tm_hour = parse2num(&s, 0, 23);
	tm->tm_min = parse2num(&s, 0, 59);
	if (utctime) {
		if (s && s[0] != 'Z' && s[0] != '\0')
			tm->tm_sec = parse2num(&s, 0, 61);
	} else {
		tm->tm_sec = parse2num(&s, 0, 61);
	}

	if (s) {
		if (s[0] == '\0')
			goto good;
		if (s[0] == 'Z' && s[1] == '\0')
			goto good;
	}
	return -1;
 good:
	return utctime ? V_ASN1_UTCTIME : V_ASN1_GENERALIZEDTIME;
}

//#endif /* HAVE_ASN1_TIME_PARSE */

/* tls_util.c */

const char *
tls_backend_version(void)
{
	return OpenSSL_version(OPENSSL_VERSION);
}

ssize_t
tls_get_connection_info(struct tls *ctx, char *buf, size_t buflen)
{
	SSL *conn = ctx->ssl_conn;
	const char *ocsp_pfx = "", *ocsp_info = "";
	const char *proto = "-", *cipher = "-";
	char dh[64];
	int used_dh_bits = ctx->used_dh_bits, used_ecdh_nid = ctx->used_ecdh_nid;
	const SSL_CIPHER *ciph_obj = NULL;

	dh[0] = 0;

	if (conn != NULL) {
		proto = SSL_get_version(conn);
		cipher = SSL_get_cipher(conn);
		ciph_obj = SSL_get_current_cipher(conn);

#ifdef SSL_get_server_tmp_key
		if (ctx->flags & TLS_CLIENT) {
			EVP_PKEY *pk = NULL;
			int ok = SSL_get_server_tmp_key(conn, &pk);
			if (ok) {
				int pk_type = EVP_PKEY_id(pk);
				if (pk_type == EVP_PKEY_DH) {
					DH *dh = EVP_PKEY_get0(pk);
					used_dh_bits = DH_size(dh) * 8;
				} else if (pk_type == EVP_PKEY_EC) {
					EC_KEY *ecdh = EVP_PKEY_get0(pk);
					const EC_GROUP *eg = EC_KEY_get0_group(ecdh);
					used_ecdh_nid = EC_GROUP_get_curve_name(eg);
				}
				EVP_PKEY_free(pk);
			}
		} else
#endif
		if (ciph_obj && !used_ecdh_nid && !used_dh_bits) {
#ifdef SSL_get_shared_curve
			int kx = SSL_CIPHER_get_kx_nid(ciph_obj);
			if (kx == NID_kx_ecdhe) {
				used_ecdh_nid = SSL_get_shared_curve(conn, 0);
			} else if (kx == NID_kx_dhe) {
				snprintf(dh, sizeof dh, "/DH=?");
			}
#endif
		}
	}

	if (used_dh_bits) {
		snprintf(dh, sizeof dh, "/DH=%d", used_dh_bits);
	} else if (used_ecdh_nid) {
		snprintf(dh, sizeof dh, "/ECDH=%s", OBJ_nid2sn(used_ecdh_nid));
	}

	if (ctx->ocsp_result) {
		ocsp_info = ctx->ocsp_result;
		ocsp_pfx = "/OCSP=";
	}

	return snprintf(buf, buflen, "%s/%s%s%s%s", proto, cipher, dh, ocsp_pfx, ocsp_info);
}

/* tls_conninfo.c */

static int
tls_hex_string(const unsigned char *in, size_t inlen, char **out,
    size_t *outlen)
{
	static const char hex[] = "0123456789abcdef";
	size_t i, len;
	char *p;

	if (outlen != NULL)
		*outlen = 0;

	if (inlen >= SIZE_MAX)
		return (-1);
	if ((*out = reallocarray(NULL, inlen + 1, 2)) == NULL)
		return (-1);

	p = *out;
	len = 0;
	for (i = 0; i < inlen; i++) {
		p[len++] = hex[(in[i] >> 4) & 0x0f];
		p[len++] = hex[in[i] & 0x0f];
	}
	p[len++] = 0;

	if (outlen != NULL)
		*outlen = len;

	return (0);
}

static void
tls_free_conninfo(struct tls_conninfo *conninfo) {
	if (conninfo != NULL) {
		free(conninfo->hash);
		conninfo->hash = NULL;
		free(conninfo->subject);
		conninfo->subject = NULL;
		free(conninfo->issuer);
		conninfo->issuer = NULL;
		free(conninfo->version);
		conninfo->version = NULL;
		free(conninfo->cipher);
		conninfo->cipher = NULL;
	}
}

static int
tls_get_peer_cert_hash(struct tls *ctx, char **hash)
{
	unsigned char d[EVP_MAX_MD_SIZE];
	char *dhex = NULL;
	unsigned int dlen;
	int rv = -1;

	*hash = NULL;
	if (ctx->ssl_peer_cert == NULL)
		return (0);

	if (X509_digest(ctx->ssl_peer_cert, EVP_sha256(), d, &dlen) != 1) {
		tls_set_errorx(ctx, "digest failed");
		goto err;
	}

	if (tls_hex_string(d, dlen, &dhex, NULL) != 0) {
		tls_set_errorx(ctx, "digest hex string failed");
		goto err;
	}

	if (asprintf(hash, "SHA256:%s", dhex) == -1) {
		tls_set_errorx(ctx, "out of memory");
		*hash = NULL;
		goto err;
	}

	rv = 0;

err:
	free(dhex);

	return (rv);
}

static int
tls_get_peer_cert_issuer(struct tls *ctx,  char **issuer)
{
	X509_NAME *name = NULL;

	*issuer = NULL;
	if (ctx->ssl_peer_cert == NULL)
		return (-1);
	if ((name = X509_get_issuer_name(ctx->ssl_peer_cert)) == NULL)
		return (-1);
	*issuer = X509_NAME_oneline(name, 0, 0);
	if (*issuer == NULL)
		return (-1);
	return (0);
}

static int
tls_get_peer_cert_subject(struct tls *ctx, char **subject)
{
	X509_NAME *name = NULL;

	*subject = NULL;
	if (ctx->ssl_peer_cert == NULL)
		return (-1);
	if ((name = X509_get_subject_name(ctx->ssl_peer_cert)) == NULL)
		return (-1);
	*subject = X509_NAME_oneline(name, 0, 0);
	if (*subject == NULL)
		return (-1);
	return (0);
}

static int
tls_get_peer_cert_times(struct tls *ctx, time_t *notbefore, time_t *notafter)
{
	struct tm before_tm, after_tm;
	ASN1_TIME *before, *after;
	int rv = -1;

	memset(&before_tm, 0, sizeof(before_tm));
	memset(&after_tm, 0, sizeof(after_tm));

	if (ctx->ssl_peer_cert != NULL) {
		if ((before = X509_get_notBefore(ctx->ssl_peer_cert)) == NULL)
			goto err;
		if ((after = X509_get_notAfter(ctx->ssl_peer_cert)) == NULL)
			goto err;
		if (asn1_time_parse((char*)before->data, before->length, &before_tm, 0) == -1)
			goto err;
		if (asn1_time_parse((char*)after->data, after->length, &after_tm, 0) == -1)
			goto err;
		if ((*notbefore = timegm(&before_tm)) == -1)
			goto err;
		if ((*notafter = timegm(&after_tm)) == -1)
			goto err;
	}
	rv = 0;
 err:
	return (rv);
}

static int
tls_get_conninfo(struct tls *ctx) {
	const char * tmp;

	tls_free_conninfo(ctx->conninfo);

	if (ctx->ssl_peer_cert != NULL) {
		if (tls_get_peer_cert_hash(ctx, &ctx->conninfo->hash) == -1)
			goto err;
		if (tls_get_peer_cert_subject(ctx, &ctx->conninfo->subject)
		    == -1)
			goto err;
		if (tls_get_peer_cert_issuer(ctx, &ctx->conninfo->issuer) == -1)
			goto err;
		if (tls_get_peer_cert_times(ctx, &ctx->conninfo->notbefore,
		    &ctx->conninfo->notafter) == -1)
			goto err;
	}
	if ((tmp = SSL_get_version(ctx->ssl_conn)) == NULL)
		goto err;
	ctx->conninfo->version = strdup(tmp);
	if (ctx->conninfo->version == NULL)
		goto err;
	if ((tmp = SSL_get_cipher(ctx->ssl_conn)) == NULL)
		goto err;
	ctx->conninfo->cipher = strdup(tmp);
	if (ctx->conninfo->cipher == NULL)
		goto err;
	return (0);
err:
	tls_free_conninfo(ctx->conninfo);
	return (-1);
}

/* tls_ocsp.c */

struct tls_ocsp_query {
	/* responder location */
	char *ocsp_url;

	/* request blob */
	uint8_t *request_data;
	size_t request_size;

	/* network state */
	BIO *bio;
	SSL_CTX *ssl_ctx;
	OCSP_REQ_CTX *http_req;

	/* cert data, this struct does not own these */
	X509 *main_cert;
	STACK_OF(X509) *extra_certs;
	SSL_CTX *cert_ssl_ctx;
};

static void
tls_ocsp_info_free(struct tls_ocsp_info *info)
{
	free(info);
}

static void
tls_ocsp_client_free(struct tls *ctx)
{
	struct tls_ocsp_query *q;
	if (!ctx)
		return;
	q = ctx->ocsp_query;
	if (q) {
		if (q->http_req)
			OCSP_REQ_CTX_free(q->http_req);
		BIO_free_all(q->bio);
		SSL_CTX_free(q->ssl_ctx);

		free(q->ocsp_url);
		free(q->request_data);
		free(q);

		ctx->ocsp_query = NULL;
	}
}

/* tls_config.c */

static int
set_string(const char **dest, const char *src)
{
	free((char *)*dest);
	*dest = NULL;
	if (src != NULL)
		if ((*dest = strdup(src)) == NULL)
			return -1;
	return 0;
}

static void *
memdup(const void *in, size_t len)
{
	void *out;

	if ((out = malloc(len)) == NULL)
		return NULL;
	memcpy(out, in, len);
	return out;
}

static int
set_mem(char **dest, size_t *destlen, const void *src, size_t srclen)
{
	free(*dest);
	*dest = NULL;
	*destlen = 0;
	if (src != NULL)
		if ((*dest = memdup(src, srclen)) == NULL)
			return -1;
	*destlen = srclen;
	return 0;
}

static struct tls_keypair *
tls_keypair_new(void)
{
	return calloc(1, sizeof(struct tls_keypair));
}

static int
tls_keypair_set_cert_file(struct tls_keypair *keypair, const char *cert_file)
{
	return set_string(&keypair->cert_file, cert_file);
}

static int
tls_keypair_set_cert_mem(struct tls_keypair *keypair, const uint8_t *cert,
    size_t len)
{
	return set_mem(&keypair->cert_mem, &keypair->cert_len, cert, len);
}

static int
tls_keypair_set_key_file(struct tls_keypair *keypair, const char *key_file)
{
	return set_string(&keypair->key_file, key_file);
}

static int
tls_keypair_set_key_mem(struct tls_keypair *keypair, const uint8_t *key,
    size_t len)
{
	if (keypair->key_mem != NULL)
		explicit_bzero(keypair->key_mem, keypair->key_len);
	return set_mem(&keypair->key_mem, &keypair->key_len, key, len);
}

int
tls_config_parse_protocols(uint32_t *protocols, const char *protostr)
{
	uint32_t proto, protos = 0;
	char *s, *p, *q;
	int negate;

	if ((s = strdup(protostr)) == NULL)
		return (-1);

	q = s;
	while ((p = strsep(&q, ",:")) != NULL) {
		while (*p == ' ' || *p == '\t')
			p++;

		negate = 0;
		if (*p == '!') {
			negate = 1;
			p++;
		}

		if (negate && protos == 0)
			protos = TLS_PROTOCOLS_ALL;

		proto = 0;
		if (strcasecmp(p, "all") == 0 ||
		    strcasecmp(p, "legacy") == 0)
			proto = TLS_PROTOCOLS_ALL;
		else if (strcasecmp(p, "default") == 0 ||
		    strcasecmp(p, "secure") == 0)
			proto = TLS_PROTOCOLS_DEFAULT;
		if (strcasecmp(p, "tlsv1") == 0)
			proto = TLS_PROTOCOL_TLSv1;
		else if (strcasecmp(p, "tlsv1.0") == 0)
			proto = TLS_PROTOCOL_TLSv1_0;
		else if (strcasecmp(p, "tlsv1.1") == 0)
			proto = TLS_PROTOCOL_TLSv1_1;
		else if (strcasecmp(p, "tlsv1.2") == 0)
			proto = TLS_PROTOCOL_TLSv1_2;

		if (proto == 0) {
			free(s);
			return (-1);
		}

		if (negate)
			protos &= ~proto;
		else
			protos |= proto;
	}

	*protocols = protos;

	free(s);

	return (0);
}

void
tls_config_set_protocols(struct tls_config *config, uint32_t protocols)
{
	config->protocols = protocols;
}

void
tls_config_set_verify_depth(struct tls_config *config, int verify_depth)
{
	config->verify_depth = verify_depth;
}

void
tls_config_prefer_ciphers_server(struct tls_config *config)
{
	config->ciphers_server = 1;
}

int
tls_config_set_ciphers(struct tls_config *config, const char *ciphers)
{
	SSL_CTX *ssl_ctx = NULL;

	if (ciphers == NULL ||
	    strcasecmp(ciphers, "default") == 0 ||
	    strcasecmp(ciphers, "secure") == 0)
		ciphers = TLS_CIPHERS_DEFAULT;
	else if (strcasecmp(ciphers, "compat") == 0 ||
	    strcasecmp(ciphers, "legacy") == 0)
		ciphers = TLS_CIPHERS_COMPAT;
	else if (strcasecmp(ciphers, "insecure") == 0 ||
	    strcasecmp(ciphers, "all") == 0)
		ciphers = TLS_CIPHERS_ALL;
	else if (strcasecmp(ciphers, "normal") == 0)
		ciphers = TLS_CIPHERS_NORMAL;
	else if (strcasecmp(ciphers, "fast") == 0)
		ciphers = TLS_CIPHERS_FAST;

	if ((ssl_ctx = SSL_CTX_new(SSLv23_method())) == NULL) {
		tls_config_set_errorx(config, "out of memory");
		goto fail;
	}
	if (SSL_CTX_set_cipher_list(ssl_ctx, ciphers) != 1) {
		tls_config_set_errorx(config, "no ciphers for '%s'", ciphers);
		goto fail;
	}

	SSL_CTX_free(ssl_ctx);
	return set_string(&config->ciphers, ciphers);

 fail:
	SSL_CTX_free(ssl_ctx);
	return -1;
}

int
tls_config_set_dheparams(struct tls_config *config, const char *params)
{
	int keylen;

	if (params == NULL || strcasecmp(params, "none") == 0)
		keylen = 0;
	else if (strcasecmp(params, "auto") == 0)
		keylen = -1;
	else if (strcasecmp(params, "legacy") == 0)
		keylen = 1024;
	else {
		tls_config_set_errorx(config, "invalid dhe param '%s'", params);
		return (-1);
	}

	config->dheparams = keylen;

	return (0);
}

int
tls_config_set_ecdhecurve(struct tls_config *config, const char *name)
{
	int nid;

	if (name == NULL || strcasecmp(name, "none") == 0)
		nid = NID_undef;
	else if (strcasecmp(name, "auto") == 0)
		nid = -1;
	else if ((nid = OBJ_txt2nid(name)) == NID_undef) {
		tls_config_set_errorx(config, "invalid ecdhe curve '%s'", name);
		return (-1);
	}

	config->ecdhecurve = nid;

	return (0);
}

int
tls_config_set_ca_file(struct tls_config *config, const char *ca_file)
{
	return set_string(&config->ca_file, ca_file);
}

int
tls_config_set_key_file(struct tls_config *config, const char *key_file)
{
	return tls_keypair_set_key_file(config->keypair, key_file);
}

int
tls_config_set_cert_file(struct tls_config *config, const char *cert_file)
{
	return tls_keypair_set_cert_file(config->keypair, cert_file);
}

void
tls_config_verify(struct tls_config *config)
{
	config->verify_cert = 1;
	config->verify_name = 1;
	config->verify_time = 1;
}

void
tls_config_insecure_noverifyname(struct tls_config *config)
{
	config->verify_name = 0;
}

void
tls_config_insecure_noverifycert(struct tls_config *config)
{
	config->verify_cert = 0;
}

void
tls_config_verify_client(struct tls_config *config)
{
	config->verify_client = 1;
}

void
tls_config_verify_client_optional(struct tls_config *config)
{
	config->verify_client = 2;
}

static void
tls_keypair_clear(struct tls_keypair *keypair)
{
	tls_keypair_set_cert_mem(keypair, NULL, 0);
	tls_keypair_set_key_mem(keypair, NULL, 0);
}

static void
tls_keypair_free(struct tls_keypair *keypair)
{
	if (keypair == NULL)
		return;

	tls_keypair_clear(keypair);

	free((char *)keypair->cert_file);
	free(keypair->cert_mem);
	free((char *)keypair->key_file);
	free(keypair->key_mem);

	free(keypair);
}

struct tls_config *
tls_config_new(void)
{
	struct tls_config *config;

	if ((config = calloc(1, sizeof(*config))) == NULL)
		return (NULL);

	if ((config->keypair = tls_keypair_new()) == NULL)
		goto err;

	/*
	 * Default configuration.
	 */
	if (tls_config_set_ca_file(config, _PATH_SSL_CA_FILE) != 0)
		goto err;
	if (tls_config_set_dheparams(config, "none") != 0)
		goto err;
	if (tls_config_set_ecdhecurve(config, "auto") != 0)
		goto err;
	if (tls_config_set_ciphers(config, "secure") != 0)
		goto err;

	tls_config_set_protocols(config, TLS_PROTOCOLS_DEFAULT);
	tls_config_set_verify_depth(config, 6);

	tls_config_prefer_ciphers_server(config);

	tls_config_verify(config);

	return (config);

 err:
	tls_config_free(config);
	return (NULL);
}

void
tls_config_free(struct tls_config *config)
{
	struct tls_keypair *kp, *nkp;

	if (config == NULL)
		return;

	for (kp = config->keypair; kp != NULL; kp = nkp) {
		nkp = kp->next;
		tls_keypair_free(kp);
	}

	free(config->error.msg);

	free((char *)config->ca_file);
	free((char *)config->ca_mem);
	free((char *)config->ca_path);
	free((char *)config->ciphers);

	free(config);
}

/* tls.c */

static struct tls_config *tls_config_default;
static int tls_initialised = 0;

int
tls_init(void)
{
	if (tls_initialised)
		return (0);

#ifdef USE_LIBSSL_OLD
	SSL_load_error_strings();
	SSL_library_init();

	if (BIO_sock_init() != 1)
		return (-1);
#endif

	if ((tls_config_default = tls_config_new()) == NULL)
		return (-1);

	tls_initialised = 1;

	return (0);
}

static void tls_compat_cleanup(void)
{
#ifdef DH_CLEANUP
	if (dh1024) { DH_free(dh1024); dh1024 = NULL; }
	if (dh2048) { DH_free(dh2048); dh2048 = NULL; }
	if (dh4096) { DH_free(dh4096); dh4096 = NULL; }
#endif
#ifdef ECDH_CLEANUP
	if (ecdh_cache) {
		EC_KEY_free(ecdh_cache);
		ecdh_cache = NULL;
	}
#endif
}

void
tls_deinit(void)
{
	if (tls_initialised) {
		tls_compat_cleanup();

		tls_config_free(tls_config_default);
		tls_config_default = NULL;

#ifdef USE_LIBSSL_OLD
		EVP_cleanup();
		CRYPTO_cleanup_all_ex_data();
		BIO_sock_cleanup();
		ERR_clear_error();
		ERR_remove_thread_state(NULL);
		ERR_free_strings();
#else
		OPENSSL_cleanup();
#endif

		tls_initialised = 0;
	}
}

const char *
tls_error(struct tls *ctx)
{
	return ctx->error.msg;
}

_PRINTF(3,0)
static int
tls_error_vset(struct tls_error *error, int errnum, const char *fmt, va_list ap)
{
	char *errmsg = NULL;
	int rv = -1;

	free(error->msg);
	error->msg = NULL;
	error->num = errnum;

	if (vasprintf(&errmsg, fmt, ap) == -1) {
		errmsg = NULL;
		goto err;
	}

	if (errnum == -1) {
		error->msg = errmsg;
		return (0);
	}

	if (asprintf(&error->msg, "%s: %s", errmsg, strerror(errnum)) == -1) {
		error->msg = NULL;
		goto err;
	}
	rv = 0;

 err:
	free(errmsg);

	return (rv);
}

int
tls_config_set_errorx(struct tls_config *config, const char *fmt, ...)
{
	va_list ap;
	int rv;

	va_start(ap, fmt);
	rv = tls_error_vset(&config->error, -1, fmt, ap);
	va_end(ap);

	return (rv);
}

static int
tls_set_error(struct tls *ctx, const char *fmt, ...)
{
	va_list ap;
	int errnum, rv;

	errnum = errno;

	va_start(ap, fmt);
	rv = tls_error_vset(&ctx->error, errnum, fmt, ap);
	va_end(ap);

	return (rv);
}

static int
tls_set_errorx(struct tls *ctx, const char *fmt, ...)
{
	va_list ap;
	int rv;

	va_start(ap, fmt);
	rv = tls_error_vset(&ctx->error, -1, fmt, ap);
	va_end(ap);

	return (rv);
}

static int
tls_do_abort(struct tls *ctx)
{
	int ssl_ret, rv;

	ssl_ret = SSL_shutdown(ctx->ssl_conn);
	if (ssl_ret < 0) {
		rv = tls_ssl_error(ctx, ctx->ssl_conn, ssl_ret, "shutdown");
		if (rv == TLS_WANT_POLLIN || rv == TLS_WANT_POLLOUT)
			return (rv);
	}

	tls_set_errorx(ctx, "unexpected handshake, closing connection");
	return -1;
}

static struct tls *
tls_new(void)
{
	struct tls *ctx;

	if ((ctx = calloc(1, sizeof(*ctx))) == NULL)
		return (NULL);

	ctx->config = tls_config_default;

	tls_reset(ctx);

	return (ctx);
}

int
tls_configure(struct tls *ctx, struct tls_config *config)
{
	if (config == NULL)
		config = tls_config_default;

	ctx->config = config;

	if ((ctx->flags & TLS_SERVER) != 0)
		return (tls_configure_server(ctx));

	return (0);
}

static int
tls_configure_keypair(struct tls *ctx, SSL_CTX *ssl_ctx,
    struct tls_keypair *keypair, int required)
{
	EVP_PKEY *pkey = NULL;
	X509 *cert = NULL;
	BIO *bio = NULL;

	if (!required &&
	    keypair->cert_mem == NULL &&
	    keypair->key_mem == NULL &&
	    keypair->cert_file == NULL &&
	    keypair->key_file == NULL)
		return(0);

	if (keypair->cert_mem != NULL) {
		if (keypair->cert_len > INT_MAX) {
			tls_set_errorx(ctx, "certificate too long");
			goto err;
		}

		if (SSL_CTX_use_certificate_chain_mem(ssl_ctx,
		    keypair->cert_mem, keypair->cert_len) != 1) {
			tls_set_errorx(ctx, "failed to load certificate");
			goto err;
		}
		cert = NULL;
	}
	if (keypair->key_mem != NULL) {
		if (keypair->key_len > INT_MAX) {
			tls_set_errorx(ctx, "key too long");
			goto err;
		}

		if ((bio = BIO_new_mem_buf(keypair->key_mem,
		    keypair->key_len)) == NULL) {
			tls_set_errorx(ctx, "failed to create buffer");
			goto err;
		}
		if ((pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL,
		    NULL)) == NULL) {
			tls_set_errorx(ctx, "failed to read private key");
			goto err;
		}
		if (SSL_CTX_use_PrivateKey(ssl_ctx, pkey) != 1) {
			tls_set_errorx(ctx, "failed to load private key");
			goto err;
		}
		BIO_free(bio);
		bio = NULL;
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}

	if (keypair->cert_file != NULL) {
		if (SSL_CTX_use_certificate_chain_file(ssl_ctx,
		    keypair->cert_file) != 1) {
			tls_set_errorx(ctx, "failed to load certificate file");
			goto err;
		}
	}
	if (keypair->key_file != NULL) {
		if (SSL_CTX_use_PrivateKey_file(ssl_ctx,
		    keypair->key_file, SSL_FILETYPE_PEM) != 1) {
			tls_set_errorx(ctx, "failed to load private key file");
			goto err;
		}
	}

	if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
		tls_set_errorx(ctx, "private/public key mismatch");
		goto err;
	}

	return (0);

 err:
	EVP_PKEY_free(pkey);
	X509_free(cert);
	BIO_free(bio);

	return (1);
}

static void
tls_info_callback(const SSL *ssl, int where, int rc)
{
	struct tls *ctx = SSL_get_app_data(ssl);

#ifdef USE_LIBSSL_INTERNALS
	if (!(ctx->state & TLS_HANDSHAKE_COMPLETE) && ssl->s3) {
		/* steal info about used DH key */
		if (ssl->s3->tmp.dh && !ctx->used_dh_bits) {
			ctx->used_dh_bits = DH_size(ssl->s3->tmp.dh) * 8;
		} else if (ssl->s3->tmp.ecdh && !ctx->used_ecdh_nid) {
			ctx->used_ecdh_nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(ssl->s3->tmp.ecdh));
		}
	}
#endif

	/* detect renegotation on established connection */
	if (where & SSL_CB_HANDSHAKE_START) {
		if (ctx->state & TLS_HANDSHAKE_COMPLETE)
			ctx->state |= TLS_DO_ABORT;
	}
}

static int
tls_configure_ssl(struct tls *ctx)
{
	SSL_CTX_set_mode(ctx->ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
	SSL_CTX_set_mode(ctx->ssl_ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
	SSL_CTX_set_mode(ctx->ssl_ctx, SSL_MODE_RELEASE_BUFFERS);

	SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_SSLv2);
	SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_SSLv3);

	SSL_CTX_clear_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1);
	SSL_CTX_clear_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1_1);
	SSL_CTX_clear_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1_2);

	if ((ctx->config->protocols & TLS_PROTOCOL_TLSv1_0) == 0)
		SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1);
	if ((ctx->config->protocols & TLS_PROTOCOL_TLSv1_1) == 0)
		SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1_1);
	if ((ctx->config->protocols & TLS_PROTOCOL_TLSv1_2) == 0)
		SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1_2);

	if (ctx->config->ciphers != NULL) {
		if (SSL_CTX_set_cipher_list(ctx->ssl_ctx,
		    ctx->config->ciphers) != 1) {
			tls_set_errorx(ctx, "failed to set ciphers");
			goto err;
		}
	}

	SSL_CTX_set_info_callback(ctx->ssl_ctx, tls_info_callback);

#ifdef X509_V_FLAG_NO_CHECK_TIME
	if (ctx->config->verify_time == 0) {
		X509_VERIFY_PARAM *vfp = SSL_CTX_get0_param(ctx->ssl_ctx);
		X509_VERIFY_PARAM_set_flags(vfp, X509_V_FLAG_NO_CHECK_TIME);
	}
#endif

	return (0);

 err:
	return (-1);
}

static int
tls_configure_ssl_verify(struct tls *ctx, int verify)
{
	SSL_CTX_set_verify(ctx->ssl_ctx, verify, NULL);

	if (ctx->config->ca_mem != NULL) {
		/* XXX do this in set. */
		if (ctx->config->ca_len > INT_MAX) {
			tls_set_errorx(ctx, "ca too long");
			goto err;
		}
		if (SSL_CTX_load_verify_mem(ctx->ssl_ctx,
		    ctx->config->ca_mem, ctx->config->ca_len) != 1) {
			tls_set_errorx(ctx, "ssl verify memory setup failure");
			goto err;
		}
	} else if (SSL_CTX_load_verify_locations(ctx->ssl_ctx,
	    ctx->config->ca_file, ctx->config->ca_path) != 1) {
		tls_set_errorx(ctx, "ssl verify setup failure");
		goto err;
	}
	if (ctx->config->verify_depth >= 0)
		SSL_CTX_set_verify_depth(ctx->ssl_ctx,
		    ctx->config->verify_depth);

	return (0);

 err:
	return (-1);
}

void
tls_free(struct tls *ctx)
{
	if (ctx == NULL)
		return;
	tls_reset(ctx);
	free(ctx);
}

void
tls_reset(struct tls *ctx)
{
	SSL_CTX_free(ctx->ssl_ctx);
	SSL_free(ctx->ssl_conn);
	X509_free(ctx->ssl_peer_cert);

	ctx->ssl_conn = NULL;
	ctx->ssl_ctx = NULL;
	ctx->ssl_peer_cert = NULL;

	ctx->socket = -1;
	ctx->state = 0;

	free(ctx->servername);
	ctx->servername = NULL;

	free(ctx->error.msg);
	ctx->error.msg = NULL;
	ctx->error.num = -1;

	tls_free_conninfo(ctx->conninfo);
	free(ctx->conninfo);
	ctx->conninfo = NULL;

	ctx->used_dh_bits = 0;
	ctx->used_ecdh_nid = 0;

	tls_ocsp_info_free(ctx->ocsp_info);
	ctx->ocsp_info = NULL;
	ctx->ocsp_result = NULL;

	if (ctx->flags & TLS_OCSP_CLIENT)
		tls_ocsp_client_free(ctx);
}

static int
tls_ssl_error(struct tls *ctx, SSL *ssl_conn, int ssl_ret, const char *prefix)
{
	const char *errstr = "unknown error";
	unsigned long err;
	int ssl_err;

	ssl_err = SSL_get_error(ssl_conn, ssl_ret);
	switch (ssl_err) {
	case SSL_ERROR_NONE:
	case SSL_ERROR_ZERO_RETURN:
		return (0);

	case SSL_ERROR_WANT_READ:
		return (TLS_WANT_POLLIN);

	case SSL_ERROR_WANT_WRITE:
		return (TLS_WANT_POLLOUT);

	case SSL_ERROR_SYSCALL:
		if ((err = ERR_peek_error()) != 0) {
			errstr = ERR_error_string(err, NULL);
		} else if (ssl_ret == 0) {
			if ((ctx->state & TLS_HANDSHAKE_COMPLETE) != 0) {
				ctx->state |= TLS_EOF_NO_CLOSE_NOTIFY;
				return (0);
			}
			errstr = "unexpected EOF";
		} else if (ssl_ret == -1) {
			errstr = strerror(errno);
		}
		tls_set_errorx(ctx, "%s failed: %s", prefix, errstr);
		return (-1);

	case SSL_ERROR_SSL:
		if ((err = ERR_peek_error()) != 0) {
			errstr = ERR_error_string(err, NULL);
		}
		tls_set_errorx(ctx, "%s failed: %s", prefix, errstr);
		return (-1);

	case SSL_ERROR_WANT_CONNECT:
	case SSL_ERROR_WANT_ACCEPT:
	case SSL_ERROR_WANT_X509_LOOKUP:
	default:
		tls_set_errorx(ctx, "%s failed (%i)", prefix, ssl_err);
		return (-1);
	}
}

int
tls_handshake(struct tls *ctx)
{
	int rv = -1;

	if ((ctx->flags & (TLS_CLIENT | TLS_SERVER_CONN)) == 0) {
		tls_set_errorx(ctx, "invalid operation for context");
		goto out;
	}

	if (ctx->conninfo == NULL &&
	    (ctx->conninfo = calloc(1, sizeof(*ctx->conninfo))) == NULL)
		goto out;

	if ((ctx->flags & TLS_CLIENT) != 0)
		rv = tls_handshake_client(ctx);
	else if ((ctx->flags & TLS_SERVER_CONN) != 0)
		rv = tls_handshake_server(ctx);

	if (rv == 0) {
		ctx->ssl_peer_cert =  SSL_get_peer_certificate(ctx->ssl_conn);
		if (tls_get_conninfo(ctx) == -1)
		    rv = -1;
	}
 out:
	/* Prevent callers from performing incorrect error handling */
	errno = 0;
	return (rv);
}

ssize_t
tls_read(struct tls *ctx, void *buf, size_t buflen)
{
	ssize_t rv = -1;
	int ssl_ret;

	if (ctx->state & TLS_DO_ABORT) {
		rv = tls_do_abort(ctx);
		goto out;
	}

	if ((ctx->state & TLS_HANDSHAKE_COMPLETE) == 0) {
		if ((rv = tls_handshake(ctx)) != 0)
			goto out;
	}

	if (buflen > INT_MAX) {
		tls_set_errorx(ctx, "buflen too long");
		goto out;
	}

	ERR_clear_error();
	if ((ssl_ret = SSL_read(ctx->ssl_conn, buf, buflen)) > 0) {
		rv = (ssize_t)ssl_ret;
		goto out;
	}
	rv = (ssize_t)tls_ssl_error(ctx, ctx->ssl_conn, ssl_ret, "read");

 out:
	/* Prevent callers from performing incorrect error handling */
	errno = 0;
	return (rv);
}

ssize_t
tls_write(struct tls *ctx, const void *buf, size_t buflen)
{
	ssize_t rv = -1;
	int ssl_ret;

	if (ctx->state & TLS_DO_ABORT) {
		rv = tls_do_abort(ctx);
		goto out;
	}

	if ((ctx->state & TLS_HANDSHAKE_COMPLETE) == 0) {
		if ((rv = tls_handshake(ctx)) != 0)
			goto out;
	}

	if (buflen > INT_MAX) {
		tls_set_errorx(ctx, "buflen too long");
		goto out;
	}

	ERR_clear_error();
	if ((ssl_ret = SSL_write(ctx->ssl_conn, buf, buflen)) > 0) {
		rv = (ssize_t)ssl_ret;
		goto out;
	}
	rv =  (ssize_t)tls_ssl_error(ctx, ctx->ssl_conn, ssl_ret, "write");

 out:
	/* Prevent callers from performing incorrect error handling */
	errno = 0;
	return (rv);
}

int
tls_close(struct tls *ctx)
{
	int ssl_ret;
	int rv = 0;

	if ((ctx->flags & (TLS_CLIENT | TLS_SERVER_CONN)) == 0) {
		tls_set_errorx(ctx, "invalid operation for context");
		rv = -1;
		goto out;
	}

	if (ctx->ssl_conn != NULL) {
		ERR_clear_error();
		ssl_ret = SSL_shutdown(ctx->ssl_conn);
		if (ssl_ret < 0) {
			rv = tls_ssl_error(ctx, ctx->ssl_conn, ssl_ret,
			    "shutdown");
			if (rv == TLS_WANT_POLLIN || rv == TLS_WANT_POLLOUT)
				goto out;
		}
	}

	if (ctx->socket != -1) {
		if (shutdown(ctx->socket, SHUT_RDWR) != 0) {
			if (rv == 0 &&
			    errno != ENOTCONN && errno != ECONNRESET) {
				tls_set_error(ctx, "shutdown");
				rv = -1;
			}
		}
		if (close(ctx->socket) != 0) {
			if (rv == 0) {
				tls_set_error(ctx, "close");
				rv = -1;
			}
		}
		ctx->socket = -1;
	}

	if ((ctx->state & TLS_EOF_NO_CLOSE_NOTIFY) != 0) {
		tls_set_errorx(ctx, "EOF without close notify");
		rv = -1;
	}

 out:
	/* Prevent callers from performing incorrect error handling */
	errno = 0;
	return (rv);
}

/* tls_server.c */

static struct tls *
tls_server_conn(struct tls *ctx)
{
	struct tls *conn_ctx;

	if ((conn_ctx = tls_new()) == NULL)
		return (NULL);

	conn_ctx->flags |= TLS_SERVER_CONN;

	return (conn_ctx);
}

static int
tls_configure_server(struct tls *ctx)
{
	EC_KEY *ecdh_key;
	unsigned char sid[SSL_MAX_SSL_SESSION_ID_LENGTH];

	if ((ctx->ssl_ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {
		tls_set_errorx(ctx, "ssl context failure");
		goto err;
	}

	if (tls_configure_ssl(ctx) != 0)
		goto err;
	if (tls_configure_keypair(ctx, ctx->ssl_ctx, ctx->config->keypair, 1) != 0)
		goto err;
	if (ctx->config->verify_client != 0) {
		int verify = SSL_VERIFY_PEER;
		if (ctx->config->verify_client == 1)
			verify |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
		if (tls_configure_ssl_verify(ctx, verify) == -1)
			goto err;
	}

	if (ctx->config->dheparams == -1)
		SSL_CTX_set_dh_auto(ctx->ssl_ctx, 1);
	else if (ctx->config->dheparams == 1024)
		SSL_CTX_set_dh_auto(ctx->ssl_ctx, 2);

	if (ctx->config->ecdhecurve == -1) {
		(void) SSL_CTX_set_ecdh_auto(ctx->ssl_ctx, 1); // XXX
	} else if (ctx->config->ecdhecurve != NID_undef) {
		if ((ecdh_key = EC_KEY_new_by_curve_name(
		    ctx->config->ecdhecurve)) == NULL) {
			tls_set_errorx(ctx, "failed to set ECDHE curve");
			goto err;
		}
		SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_SINGLE_ECDH_USE);
		SSL_CTX_set_tmp_ecdh(ctx->ssl_ctx, ecdh_key);
		EC_KEY_free(ecdh_key);
	}

	if (ctx->config->ciphers_server == 1)
		SSL_CTX_set_options(ctx->ssl_ctx,
		    SSL_OP_CIPHER_SERVER_PREFERENCE);

#if 0
	if (SSL_CTX_set_tlsext_status_cb(ctx->ssl_ctx, tls_ocsp_stapling_callback) != 1) {
		tls_set_errorx(ctx, "ssl OCSP stapling setup failure");
		goto err;
	}
#endif

	/*
	 * Set session ID context to a random value.  We don't support
	 * persistent caching of sessions so it is OK to set a temporary
	 * session ID context that is valid during run time.
	 */
	if (!RAND_bytes(sid, sizeof(sid))) {
		tls_set_errorx(ctx, "failed to generate session id");
		goto err;
	}
	if (!SSL_CTX_set_session_id_context(ctx->ssl_ctx, sid, sizeof(sid))) {
		tls_set_errorx(ctx, "failed to set session id context");
		goto err;
	}

	return (0);

 err:
	return (-1);
}

int
tls_accept_fds(struct tls *ctx, struct tls **cctx, int fd_read, int fd_write)
{
	struct tls *conn_ctx = NULL;

	if ((ctx->flags & TLS_SERVER) == 0) {
		tls_set_errorx(ctx, "not a server context");
		goto err;
	}

	if ((conn_ctx = tls_server_conn(ctx)) == NULL) {
		tls_set_errorx(ctx, "connection context failure");
		goto err;
	}

	if ((conn_ctx->ssl_conn = SSL_new(ctx->ssl_ctx)) == NULL) {
		tls_set_errorx(ctx, "ssl failure");
		goto err;
	}
	if (SSL_set_app_data(conn_ctx->ssl_conn, conn_ctx) != 1) {
		tls_set_errorx(ctx, "ssl application data failure");
		goto err;
	}
	if (SSL_set_rfd(conn_ctx->ssl_conn, fd_read) != 1 ||
	    SSL_set_wfd(conn_ctx->ssl_conn, fd_write) != 1) {
		tls_set_errorx(ctx, "ssl file descriptor failure");
		goto err;
	}

	*cctx = conn_ctx;

	return (0);

 err:
	tls_free(conn_ctx);

	*cctx = NULL;

	return (-1);
}

static int
tls_handshake_server(struct tls *ctx)
{
	int ssl_ret;
	int rv = -1;

	if ((ctx->flags & TLS_SERVER_CONN) == 0) {
		tls_set_errorx(ctx, "not a server connection context");
		goto err;
	}

	ERR_clear_error();
	if ((ssl_ret = SSL_accept(ctx->ssl_conn)) != 1) {
		rv = tls_ssl_error(ctx, ctx->ssl_conn, ssl_ret, "handshake");
		goto err;
	}

	ctx->state |= TLS_HANDSHAKE_COMPLETE;
	rv = 0;

 err:
	return (rv);
}

struct tls *
tls_server(void)
{
	struct tls *ctx;

	if ((ctx = tls_new()) == NULL)
		return (NULL);

	ctx->flags |= TLS_SERVER;

	return (ctx);
}

struct tls *
tls_client(void)
{
	struct tls *ctx;

	if ((ctx = tls_new()) == NULL)
		return (NULL);

	ctx->flags |= TLS_CLIENT;

	return (ctx);
}

int
tls_connect_fds(struct tls *ctx, int fd_read, int fd_write,
    const char *servername)
{
	union tls_addr addrbuf;
	int rv = -1;

	if ((ctx->flags & TLS_CLIENT) == 0) {
		tls_set_errorx(ctx, "not a client context");
		goto err;
	}

	if (fd_read < 0 || fd_write < 0) {
		tls_set_errorx(ctx, "invalid file descriptors");
		goto err;
	}

	if (servername != NULL) {
		if ((ctx->servername = strdup(servername)) == NULL) {
			tls_set_errorx(ctx, "out of memory");
			goto err;
		}
	}

	if ((ctx->ssl_ctx = SSL_CTX_new(SSLv23_client_method())) == NULL) {
		tls_set_errorx(ctx, "ssl context failure");
		goto err;
	}

	if (tls_configure_ssl(ctx) != 0)
		goto err;
	if (tls_configure_keypair(ctx, ctx->ssl_ctx, ctx->config->keypair, 0) != 0)
		goto err;

	if (ctx->config->verify_name) {
		if (servername == NULL) {
			tls_set_errorx(ctx, "server name not specified");
			goto err;
		}
	}

	if (ctx->config->verify_cert &&
	    (tls_configure_ssl_verify(ctx, SSL_VERIFY_PEER) == -1))
		goto err;

#ifdef TODO
	if (SSL_CTX_set_tlsext_status_cb(ctx->ssl_ctx, tls_ocsp_verify_callback) != 1) {
		tls_set_errorx(ctx, "ssl OCSP verification setup failure");
		goto err;
	}
#endif

	if ((ctx->ssl_conn = SSL_new(ctx->ssl_ctx)) == NULL) {
		tls_set_errorx(ctx, "ssl connection failure");
		goto err;
	}
	if (SSL_set_app_data(ctx->ssl_conn, ctx) != 1) {
		tls_set_errorx(ctx, "ssl application data failure");
		goto err;
	}
	if (SSL_set_rfd(ctx->ssl_conn, fd_read) != 1 ||
	    SSL_set_wfd(ctx->ssl_conn, fd_write) != 1) {
		tls_set_errorx(ctx, "ssl file descriptor failure");
		goto err;
	}
	if (SSL_set_tlsext_status_type(ctx->ssl_conn, TLSEXT_STATUSTYPE_ocsp) != 1) {
		tls_set_errorx(ctx, "ssl OCSP extension setup failure");
		goto err;
	}

	/*
	 * RFC4366 (SNI): Literal IPv4 and IPv6 addresses are not
	 * permitted in "HostName".
	 */
	if (servername != NULL &&
	    inet_pton(AF_INET, servername, &addrbuf) != 1 &&
	    inet_pton(AF_INET6, servername, &addrbuf) != 1) {
		if (SSL_set_tlsext_host_name(ctx->ssl_conn, servername) == 0) {
			tls_set_errorx(ctx, "server name indication failure");
			goto err;
		}
	}

	rv = 0;

 err:
	return (rv);
}

static int
tls_handshake_client(struct tls *ctx)
{
	X509 *cert = NULL;
	int ssl_ret;
	int rv = -1;

	if ((ctx->flags & TLS_CLIENT) == 0) {
		tls_set_errorx(ctx, "not a client context");
		goto err;
	}

	ERR_clear_error();
	if ((ssl_ret = SSL_connect(ctx->ssl_conn)) != 1) {
		rv = tls_ssl_error(ctx, ctx->ssl_conn, ssl_ret, "handshake");
		goto err;
	}

	if (ctx->config->verify_name) {
		cert = SSL_get_peer_certificate(ctx->ssl_conn);
		if (cert == NULL) {
			tls_set_errorx(ctx, "no server certificate");
			goto err;
		}
		if ((rv = tls_check_name(ctx, cert,
		    ctx->servername)) != 0) {
			if (rv != -2)
				tls_set_errorx(ctx, "name `%s' not present in"
				    " server certificate", ctx->servername);
			goto err;
		}
	}

	ctx->state |= TLS_HANDSHAKE_COMPLETE;
	rv = 0;

 err:
	X509_free(cert);

	return (rv);
}

/* tls_peer.c */

int
tls_peer_cert_provided(struct tls *ctx)
{
	return (ctx->ssl_peer_cert != NULL);
}

const char *
tls_peer_cert_subject(struct tls *ctx)
{
	if (ctx->conninfo)
		return (ctx->conninfo->subject);
	return NULL;
}

int
tls_peer_cert_contains_name(struct tls *ctx, const char *name)
{
	if (ctx->ssl_peer_cert == NULL)
		return (0);

	return (tls_check_name(ctx, ctx->ssl_peer_cert, name) == 0);
}

static int tls_match_name(const char *cert_name, const char *name);
static int tls_check_subject_altname(struct tls *ctx, X509 *cert,
    const char *name);
static int tls_check_common_name(struct tls *ctx, X509 *cert, const char *name);

static int
tls_match_name(const char *cert_name, const char *name)
{
	const char *cert_domain, *domain, *next_dot;

	if (strcasecmp(cert_name, name) == 0)
		return 0;

	/* Wildcard match? */
	if (cert_name[0] == '*') {
		/*
		 * Valid wildcards:
		 * - "*.domain.tld"
		 * - "*.sub.domain.tld"
		 * - etc.
		 * Reject "*.tld".
		 * No attempt to prevent the use of eg. "*.co.uk".
		 */
		cert_domain = &cert_name[1];
		/* Disallow "*"  */
		if (cert_domain[0] == '\0')
			return -1;
		/* Disallow "*foo" */
		if (cert_domain[0] != '.')
			return -1;
		/* Disallow "*.." */
		if (cert_domain[1] == '.')
			return -1;
		next_dot = strchr(&cert_domain[1], '.');
		/* Disallow "*.bar" */
		if (next_dot == NULL)
			return -1;
		/* Disallow "*.bar.." */
		if (next_dot[1] == '.')
			return -1;

		domain = strchr(name, '.');

		/* No wildcard match against a name with no host part. */
		if (name[0] == '.')
			return -1;
		/* No wildcard match against a name with no domain part. */
		if (domain == NULL || strlen(domain) == 1)
			return -1;

		if (strcasecmp(cert_domain, domain) == 0)
			return 0;
	}

	return -1;
}

/* See RFC 5280 section 4.2.1.6 for SubjectAltName details. */
static int
tls_check_subject_altname(struct tls *ctx, X509 *cert, const char *name)
{
	STACK_OF(GENERAL_NAME) *altname_stack = NULL;
	union tls_addr addrbuf;
	int addrlen, type;
	int count, i;
	int rv = -1;

	altname_stack = X509_get_ext_d2i(cert, NID_subject_alt_name,
	    NULL, NULL);
	if (altname_stack == NULL)
		return -1;

	if (inet_pton(AF_INET, name, &addrbuf) == 1) {
		type = GEN_IPADD;
		addrlen = 4;
	} else if (inet_pton(AF_INET6, name, &addrbuf) == 1) {
		type = GEN_IPADD;
		addrlen = 16;
	} else {
		type = GEN_DNS;
		addrlen = 0;
	}

	count = sk_GENERAL_NAME_num(altname_stack);
	for (i = 0; i < count; i++) {
		GENERAL_NAME	*altname;

		altname = sk_GENERAL_NAME_value(altname_stack, i);

		if (altname->type != type)
			continue;

		if (type == GEN_DNS) {
			const void	*data;
			int		 format, len;

			format = ASN1_STRING_type(altname->d.dNSName);
			if (format == V_ASN1_IA5STRING) {
				data = ASN1_STRING_get0_data(altname->d.dNSName);
				len = ASN1_STRING_length(altname->d.dNSName);

				if (len < 0 || len != (int)strlen(data)) {
					tls_set_errorx(ctx,
					    "error verifying name '%s': "
					    "NUL byte in subjectAltName, "
					    "probably a malicious certificate",
					    name);
					rv = -2;
					break;
				}

				/*
				 * Per RFC 5280 section 4.2.1.6:
				 * " " is a legal domain name, but that
				 * dNSName must be rejected.
				 */
				if (strcmp(data, " ") == 0) {
					tls_set_error(ctx,
					    "error verifying name '%s': "
					    "a dNSName of \" \" must not be "
					    "used", name);
					rv = -2;
					break;
				}

				if (tls_match_name(data, name) == 0) {
					rv = 0;
					break;
				}
			} else {
#ifdef DEBUG
				fprintf(stdout, "%s: unhandled subjectAltName "
				    "dNSName encoding (%d)\n", getprogname(),
				    format);
#endif
			}

		} else if (type == GEN_IPADD) {
			const unsigned char *data;
			int		 datalen;

			datalen = ASN1_STRING_length(altname->d.iPAddress);
			data = ASN1_STRING_get0_data(altname->d.iPAddress);

			if (datalen < 0) {
				tls_set_errorx(ctx,
				    "Unexpected negative length for an "
				    "IP address: %d", datalen);
				rv = -2;
				break;
			}

			/*
			 * Per RFC 5280 section 4.2.1.6:
			 * IPv4 must use 4 octets and IPv6 must use 16 octets.
			 */
			if (datalen == addrlen &&
			    memcmp(data, &addrbuf, addrlen) == 0) {
				rv = 0;
				break;
			}
		}
	}

	sk_GENERAL_NAME_pop_free(altname_stack, GENERAL_NAME_free);
	return rv;
}

static int
tls_check_common_name(struct tls *ctx, X509 *cert, const char *name)
{
	X509_NAME *subject_name;
	char *common_name = NULL;
	union tls_addr addrbuf;
	int common_name_len;
	int rv = -1;

	subject_name = X509_get_subject_name(cert);
	if (subject_name == NULL)
		goto out;

	common_name_len = X509_NAME_get_text_by_NID(subject_name,
	    NID_commonName, NULL, 0);
	if (common_name_len < 0)
		goto out;

	common_name = calloc(common_name_len + 1, 1);
	if (common_name == NULL)
		goto out;

	X509_NAME_get_text_by_NID(subject_name, NID_commonName, common_name,
	    common_name_len + 1);

	/* NUL bytes in CN? */
	if (common_name_len != (int)strlen(common_name)) {
		tls_set_errorx(ctx, "error verifying name '%s': "
		    "NUL byte in Common Name field, "
		    "probably a malicious certificate", name);
		rv = -2;
		goto out;
	}

	if (inet_pton(AF_INET,  name, &addrbuf) == 1 ||
	    inet_pton(AF_INET6, name, &addrbuf) == 1) {
		/*
		 * We don't want to attempt wildcard matching against IP
		 * addresses, so perform a simple comparison here.
		 */
		if (strcmp(common_name, name) == 0)
			rv = 0;
		else
			rv = -1;
		goto out;
	}

	if (tls_match_name(common_name, name) == 0)
		rv = 0;
 out:
	free(common_name);
	return rv;
}

int
tls_check_name(struct tls *ctx, X509 *cert, const char *name)
{
	int	rv;

	rv = tls_check_subject_altname(ctx, cert, name);
	if (rv == 0 || rv == -2)
		return rv;

	return tls_check_common_name(ctx, cert, name);
}

//#endif /* !USE_TLS */
