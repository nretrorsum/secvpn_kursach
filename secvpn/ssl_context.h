#pragma once

#include <openssl/ssl.h>

class SslContext {
public:
    SslContext();
    ~SslContext();

    // Ініціалізація ролі
    bool initServer();  // TLS_server_method, verify peer + fail if no cert
    bool initClient();  // TLS_client_method, verify peer

    // Завантаження сертифікатів
    bool loadCert(const char* certPath);
    bool loadKey(const char* keyPath);
    bool loadCA(const char* caPath);

    // Створення SSL з'єднання з цього контексту
    SSL* createSSL(int fd);

    // Доступ до raw-вказівника
    SSL_CTX* raw();

private:
    SSL_CTX* ctx_;
};
