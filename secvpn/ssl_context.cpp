#include "ssl_context.h"
#include <openssl/err.h>
#include <stdio.h>

SslContext::SslContext() : ctx_(nullptr) {}

SslContext::~SslContext() {
    if (ctx_) {
        SSL_CTX_free(ctx_);
    }
}

bool SslContext::initServer() {
    ctx_ = SSL_CTX_new(TLS_server_method());
    if (ctx_ == nullptr) {
        fprintf(stderr, "не вдалось створити серверний SSL_CTX\n");
        return false;
    }

    // Тільки TLS 1.3
    SSL_CTX_set_min_proto_version(ctx_, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx_, TLS1_3_VERSION);

    // AES-256-GCM як єдиний ciphersuite
    SSL_CTX_set_ciphersuites(ctx_, "TLS_AES_256_GCM_SHA384");

    // mTLS — вимагаємо сертифікат від клієнта
    SSL_CTX_set_verify(ctx_,
        SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
        nullptr);

    return true;
}

bool SslContext::initClient() {
    ctx_ = SSL_CTX_new(TLS_client_method());
    if (ctx_ == nullptr) {
        fprintf(stderr, "не вдалось створити клієнтський SSL_CTX\n");
        return false;
    }

    // Тільки TLS 1.3
    SSL_CTX_set_min_proto_version(ctx_, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx_, TLS1_3_VERSION);

    // AES-256-GCM
    SSL_CTX_set_ciphersuites(ctx_, "TLS_AES_256_GCM_SHA384");

    // Перевіряємо сертифікат сервера
    SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, nullptr);

    return true;
}

bool SslContext::loadCert(const char* certPath) {
    if (SSL_CTX_use_certificate_file(ctx_, certPath, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "не вдалось завантажити сертифікат з %s\n", certPath);
        return false;
    }
    return true;
}

bool SslContext::loadKey(const char* keyPath) {
    if (SSL_CTX_use_PrivateKey_file(ctx_, keyPath, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "не вдалось завантажити ключ з %s\n", keyPath);
        return false;
    }
    // Перевіряємо що ключ відповідає сертифікату
    if (SSL_CTX_check_private_key(ctx_) != 1) {
        fprintf(stderr, "ключ не відповідає сертифікату\n");
        return false;
    }
    return true;
}

bool SslContext::loadCA(const char* caPath) {
    if (SSL_CTX_load_verify_locations(ctx_, caPath, nullptr) != 1) {
        fprintf(stderr, "не вдалось завантажити CA з %s\n", caPath);
        return false;
    }
    return true;
}

SSL* SslContext::createSSL(int fd) {
    SSL* ssl = SSL_new(ctx_);
    if (ssl == nullptr) {
        fprintf(stderr, "не вдалось створити SSL з'єднання\n");
        return nullptr;
    }
    SSL_set_fd(ssl, fd);
    return ssl;
}

SSL_CTX* SslContext::raw() {
    return ctx_;
}
