#pragma once

#include <openssl/ssl.h>

class SslConnection {
public:
    // Приймає SSL* створений через SslContext::createSSL(fd)
    explicit SslConnection(SSL* ssl);
    ~SslConnection();

    // Handshake
    bool accept();   // серверна сторона — SSL_accept
    bool connect();  // клієнтська сторона — SSL_connect

    // Шифроване читання/запис
    int read(void* buf, int len);
    int write(const void* buf, int len);

    // Закриття
    void shutdown();

    // Доступ до raw SSL*
    SSL* raw();

private:
    SSL* ssl_;
};
