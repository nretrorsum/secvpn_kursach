#include "libsecvpn.h"
#include "pem_file_io.h"
#include "ssl_context.h"
#include "ssl_connection.h"
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <stdio.h>

int secvpn_generate_ca(const char *cn, const char *out_cert, const char *out_key) {
    // Генеруємо пару ключів
    EVP_PKEY *pkey = EVP_RSA_gen(4096);
    if (pkey == NULL) {
        fprintf(stderr, "помилка генерації ключа\n");
        return -1;
    }

    // Створюємо порожній сертифікат
    X509 *cert = X509_new();
    if (cert == NULL) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    // Версія 3 (значення 2 = версія 3, бо нумерація з 0)
    X509_set_version(cert, 2);

    // Унікальний серійний номер
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

    // Термін дії — 10 років
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert),
                    (long)60 * 60 * 24 * 365 * 10);

    // Вставляємо публічний ключ
    X509_set_pubkey(cert, pkey);

    // Встановлюємо ім'я (CN)
    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN",
        MBSTRING_ASC,
        (const unsigned char *)cn,
        -1, -1, 0);

    // Issuer = Subject для CA (самопідписаний)
    X509_set_issuer_name(cert, name);

    // Позначаємо що це CA — може підписувати інші сертифікати
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);

    X509_EXTENSION *ext = X509V3_EXT_conf_nid(
        NULL, &ctx,
        NID_basic_constraints,
        "critical,CA:TRUE"
    );
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);

    // Підписуємо сертифікат своїм ключем
    if (X509_sign(cert, pkey, EVP_sha256()) == 0) {
        fprintf(stderr, "помилка підпису\n");
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return -1;
    }

    // Зберігаємо сертифікат і ключ у файли
    if (PemFileIO::writeCert(out_cert, cert) != 0 ||
        PemFileIO::writeKey(out_key, pkey) != 0) {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return -1;
    }

    // Звільняємо пам'ять
    X509_free(cert);
    EVP_PKEY_free(pkey);

    printf("CA створено: %s, %s\n", out_cert, out_key);
    return 0;
}

int secvpn_generate_cert(const char *ca_cert_path, const char *ca_key_path,
                         const char *cn,
                         const char *out_cert, const char *out_key) {

    // === Крок 1: Завантажуємо CA сертифікат і ключ ===
    X509 *ca_cert = PemFileIO::readCert(ca_cert_path);
    if (ca_cert == NULL) {
        return -1;
    }

    EVP_PKEY *ca_key = PemFileIO::readKey(ca_key_path);
    if (ca_key == NULL) {
        X509_free(ca_cert);
        return -1;
    }

    // === Крок 2: Генеруємо новий ключ ===
    EVP_PKEY *private_key = EVP_RSA_gen(2048);
    if (private_key == NULL) {
        fprintf(stderr, "не вдалось згенерувати ключ\n");
        X509_free(ca_cert);
        EVP_PKEY_free(ca_key);
        return -1;
    }

    // === Крок 3: Створюємо порожній сертифікат ===
    X509 *cert = X509_new();
    if (cert == NULL) {
        EVP_PKEY_free(private_key);
        X509_free(ca_cert);
        EVP_PKEY_free(ca_key);
        return -1;
    }

    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 2);

    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), (long)60 * 60 * 24 * 365);

    X509_set_pubkey(cert, private_key);

    // === Крок 4: Встановлюємо CN ===
    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN",
        MBSTRING_ASC,
        (const unsigned char *)cn,
        -1, -1, 0);
    X509_set_subject_name(cert, name);

    // === Крок 5: Issuer = CA ===
    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));

    // === Крок 6: Підписуємо ключем CA ===
    if (X509_sign(cert, ca_key, EVP_sha256()) == 0) {
        fprintf(stderr, "не вдалось підписати сертифікат\n");
        X509_free(cert);
        EVP_PKEY_free(private_key);
        X509_free(ca_cert);
        EVP_PKEY_free(ca_key);
        return -1;
    }

    // === Крок 7: Зберігаємо сертифікат і ключ у файли ===
    if (PemFileIO::writeCert(out_cert, cert) != 0 ||
        PemFileIO::writeKey(out_key, private_key) != 0) {
        X509_free(cert);
        EVP_PKEY_free(private_key);
        X509_free(ca_cert);
        EVP_PKEY_free(ca_key);
        return -1;
    }

    // === Звільняємо всю пам'ять ===
    X509_free(cert);
    EVP_PKEY_free(private_key);
    X509_free(ca_cert);
    EVP_PKEY_free(ca_key);

    printf("сертифікат створено: %s, %s\n", out_cert, out_key);
    return 0;
}

// =====================================================
// C API для CGo — обгортки над C++ класами
// =====================================================

void* secvpn_ctx_new_server(void) {
    SslContext* ctx = new SslContext();
    if (!ctx->initServer()) {
        delete ctx;
        return NULL;
    }
    return (void*)ctx;
}

void* secvpn_ctx_new_client(void) {
    SslContext* ctx = new SslContext();
    if (!ctx->initClient()) {
        delete ctx;
        return NULL;
    }
    return (void*)ctx;
}

void secvpn_ctx_free(void *ctx) {
    delete (SslContext*)ctx;
}

int secvpn_ctx_load_cert(void *ctx, const char *path) {
    return ((SslContext*)ctx)->loadCert(path) ? 0 : -1;
}

int secvpn_ctx_load_key(void *ctx, const char *path) {
    return ((SslContext*)ctx)->loadKey(path) ? 0 : -1;
}

int secvpn_ctx_load_ca(void *ctx, const char *path) {
    return ((SslContext*)ctx)->loadCA(path) ? 0 : -1;
}

void* secvpn_ssl_new(void *ctx, int fd) {
    SSL* ssl = ((SslContext*)ctx)->createSSL(fd);
    if (ssl == NULL) {
        return NULL;
    }
    SslConnection* conn = new SslConnection(ssl);
    return (void*)conn;
}

void secvpn_ssl_close(void *conn) {
    delete (SslConnection*)conn;
}

int secvpn_ssl_accept(void *conn) {
    return ((SslConnection*)conn)->accept() ? 0 : -1;
}

int secvpn_ssl_connect(void *conn) {
    return ((SslConnection*)conn)->connect() ? 0 : -1;
}

int secvpn_ssl_read(void *conn, void *buf, int len) {
    return ((SslConnection*)conn)->read(buf, len);
}

int secvpn_ssl_write(void *conn, const void *buf, int len) {
    return ((SslConnection*)conn)->write(buf, len);
}
