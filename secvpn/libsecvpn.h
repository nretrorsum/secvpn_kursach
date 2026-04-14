// libsecvpn.h
#ifndef LIBSECVPN_H
#define LIBSECVPN_H

#ifdef __cplusplus
extern "C" {
#endif

// Генерує Root CA
// cn       — ім'я, наприклад "MyVPN-CA"
// out_cert — куди зберегти сертифікат, наприклад "ca.crt"
// out_key  — куди зберегти ключ, наприклад "ca.key"
// повертає 0 якщо успішно, -1 якщо помилка
int secvpn_generate_ca(const char *cn,
                       const char *out_cert,
                       const char *out_key);


int secvpn_generate_cert(const char *ca_cert_path,
                         const char *ca_key_path,
                         const char *cn,
                         const char *out_cert, const char *out_key);

// --- SSL Context (opaque handle) ---
void* secvpn_ctx_new_server(void);
void* secvpn_ctx_new_client(void);
void  secvpn_ctx_free(void *ctx);

int secvpn_ctx_load_cert(void *ctx, const char *path);
int secvpn_ctx_load_key(void *ctx, const char *path);
int secvpn_ctx_load_ca(void *ctx, const char *path);

// --- SSL Connection (opaque handle) ---
void* secvpn_ssl_new(void *ctx, int fd);
void  secvpn_ssl_close(void *conn);

int secvpn_ssl_accept(void *conn);
int secvpn_ssl_connect(void *conn);
int secvpn_ssl_read(void *conn, void *buf, int len);
int secvpn_ssl_write(void *conn, const void *buf, int len);

#ifdef __cplusplus
}
#endif

#endif