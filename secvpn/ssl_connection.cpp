#include "ssl_connection.h"
#include <openssl/err.h>
#include <stdio.h>

SslConnection::SslConnection(SSL* ssl) : ssl_(ssl) {}

SslConnection::~SslConnection() {
    if (ssl_) {
        shutdown();
    }
}

bool SslConnection::accept() {
    int ret = SSL_accept(ssl_);
    if (ret != 1) {
        fprintf(stderr, "SSL_accept помилка: %d\n",
                SSL_get_error(ssl_, ret));
        return false;
    }
    return true;
}

bool SslConnection::connect() {
    int ret = SSL_connect(ssl_);
    if (ret != 1) {
        fprintf(stderr, "SSL_connect помилка: %d\n",
                SSL_get_error(ssl_, ret));
        return false;
    }
    return true;
}

int SslConnection::read(void* buf, int len) {
    int n = SSL_read(ssl_, buf, len);
    if (n <= 0) {
        int err = SSL_get_error(ssl_, n);
        if (err != SSL_ERROR_ZERO_RETURN) {
            fprintf(stderr, "SSL_read помилка: %d\n", err);
        }
        return -1;
    }
    return n;
}

int SslConnection::write(const void* buf, int len) {
    int n = SSL_write(ssl_, buf, len);
    if (n <= 0) {
        fprintf(stderr, "SSL_write помилка: %d\n",
                SSL_get_error(ssl_, n));
        return -1;
    }
    return n;
}

void SslConnection::shutdown() {
    if (ssl_) {
        SSL_shutdown(ssl_);
        SSL_free(ssl_);
        ssl_ = nullptr;
    }
}

SSL* SslConnection::raw() {
    return ssl_;
}
