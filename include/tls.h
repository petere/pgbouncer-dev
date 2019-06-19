//#ifdef USE_TLS

#include <openssl/x509v3.h>

/* tls.h */

#define TLS_PROTOCOL_TLSv1_0	(1 << 1)
#define TLS_PROTOCOL_TLSv1_1	(1 << 2)
#define TLS_PROTOCOL_TLSv1_2	(1 << 3)
#define TLS_PROTOCOL_TLSv1 \
	(TLS_PROTOCOL_TLSv1_0|TLS_PROTOCOL_TLSv1_1|TLS_PROTOCOL_TLSv1_2)

#define TLS_PROTOCOLS_ALL TLS_PROTOCOL_TLSv1
#define TLS_PROTOCOLS_DEFAULT TLS_PROTOCOL_TLSv1_2

#define TLS_WANT_POLLIN		-2
#define TLS_WANT_POLLOUT	-3

/* tls_internal.h */

#define _PATH_SSL_CA_FILE USUAL_TLS_CA_FILE

// TODO: document
#define TLS_CIPHERS_COMPAT	"HIGH:+3DES:!aNULL"
#define TLS_CIPHERS_ALL		"ALL:!aNULL:!eNULL"
#define TLS_CIPHERS_DEFAULT	"HIGH+EECDH:HIGH+EDH:!SSLv3:!SHA384:!SHA256:!DSS:!aNULL"
#define TLS_CIPHERS_NORMAL	"HIGH+EECDH:HIGH+EDH:HIGH+RSA:+SHA384:+SHA256:+SSLv3:+EDH:+RSA:-3DES:3DES+RSA:!CAMELLIA:!DSS:!aNULL"
#define TLS_CIPHERS_FAST	"HIGH+EECDH:HIGH+EDH:HIGH+RSA:+AES256:+SHA256:+SHA384:+SSLv3:+EDH:+RSA:-3DES:3DES+RSA:!CAMELLIA:!DSS:!aNULL"


#define TLS_CLIENT		(1 << 0)
#define TLS_SERVER		(1 << 1)
#define TLS_SERVER_CONN		(1 << 2)
#define TLS_OCSP_CLIENT		(1 << 3)

#define TLS_EOF_NO_CLOSE_NOTIFY	(1 << 0)
#define TLS_HANDSHAKE_COMPLETE	(1 << 1)
#define TLS_DO_ABORT		(1 << 8)

union tls_addr {
	struct in_addr ip4;
	struct in6_addr ip6;
};

struct tls_error {
	char *msg;
	int num;
};

struct tls_keypair {
	struct tls_keypair *next;

	const char *cert_file;
	char *cert_mem;
	size_t cert_len;
	const char *key_file;
	char *key_mem;
	size_t key_len;
};

struct tls_config {
	struct tls_error error;

	const char *ca_file;
	const char *ca_path;
	char *ca_mem;
	size_t ca_len;
	const char *ciphers;
	int ciphers_server;
	int dheparams;
	int ecdhecurve;
	struct tls_keypair *keypair;
	const char *ocsp_file;
	char *ocsp_mem;
	size_t ocsp_len;
	uint32_t protocols;
	int verify_cert;
	int verify_client;
	int verify_depth;
	int verify_name;
	int verify_time;
};

struct tls_conninfo {
	char *issuer;
	char *subject;
	char *hash;
	char *serial;
	char *fingerprint;
	char *version;
	char *cipher;
	time_t notbefore;
	time_t notafter;
};

struct tls {
	struct tls_config *config;
	struct tls_error error;

	uint32_t flags;
	uint32_t state;

	char *servername;
	int socket;

	SSL *ssl_conn;
	SSL_CTX *ssl_ctx;
	X509 *ssl_peer_cert;
	struct tls_conninfo *conninfo;

	int used_dh_bits;
	int used_ecdh_nid;

	const char *ocsp_result;
	struct tls_ocsp_info *ocsp_info;

	struct tls_ocsp_query *ocsp_query;
};

/* tls_util.c */

const char *tls_backend_version(void);
ssize_t tls_get_connection_info(struct tls *ctx, char *buf, size_t buflen);

/* tls_config.c */

int tls_config_parse_protocols(uint32_t *_protocols, const char *_protostr);
void tls_config_set_protocols(struct tls_config *_config, uint32_t _protocols);
void tls_config_set_verify_depth(struct tls_config *_config, int _verify_depth);
void tls_config_prefer_ciphers_server(struct tls_config *_config);
int tls_config_set_ciphers(struct tls_config *_config, const char *_ciphers);
int tls_config_set_dheparams(struct tls_config *_config, const char *_params);
int tls_config_set_ecdhecurve(struct tls_config *_config, const char *_name);
int tls_config_set_ca_file(struct tls_config *_config, const char *_ca_file);
int tls_config_set_key_file(struct tls_config *_config, const char *_key_file);
int tls_config_set_cert_file(struct tls_config *_config, const char *_cert_file);
void tls_config_verify(struct tls_config *_config);
void tls_config_insecure_noverifyname(struct tls_config *_config);
void tls_config_insecure_noverifycert(struct tls_config *_config);
void tls_config_verify_client(struct tls_config *_config);
void tls_config_verify_client_optional(struct tls_config *_config);
struct tls_config *tls_config_new(void);
void tls_config_free(struct tls_config *_config);

/* tls.c */

int tls_init(void);
void tls_deinit(void);
const char *tls_error(struct tls *_ctx);
int tls_configure(struct tls *_ctx, struct tls_config *_config);
void tls_reset(struct tls *_ctx);
void tls_free(struct tls *_ctx);
int tls_handshake(struct tls *_ctx);
ssize_t tls_read(struct tls *_ctx, void *_buf, size_t _buflen);
ssize_t tls_write(struct tls *_ctx, const void *_buf, size_t _buflen);
int tls_close(struct tls *_ctx);

/* tls_server.c */

struct tls *tls_server(void);
int tls_accept_fds(struct tls *_ctx, struct tls **_cctx, int _fd_read,
    int _fd_write);

/* tls_client.c */

struct tls *tls_client(void);
int tls_connect_fds(struct tls *_ctx, int _fd_read, int _fd_write,
    const char *_servername);

/* tls_peer.c */

int tls_peer_cert_provided(struct tls *_ctx);
const char *tls_peer_cert_subject(struct tls *_ctx);
int tls_peer_cert_contains_name(struct tls *_ctx, const char *_name);

/* tls_verify.c */

int tls_check_name(struct tls *ctx, X509 *cert, const char *servername);

//#endif
