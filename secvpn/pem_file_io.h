#pragma once

#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

class PemFileIO {
public:
    // Читає X509 сертифікат з PEM-файлу, повертає nullptr якщо помилка
    static X509* readCert(const char* path);

    // Читає приватний ключ з PEM-файлу, повертає nullptr якщо помилка
    static EVP_PKEY* readKey(const char* path);

    // Записує сертифікат у PEM-файл, повертає 0 = успіх, -1 = помилка
    static int writeCert(const char* path, X509* cert);

    // Записує приватний ключ у PEM-файл (без пароля), повертає 0 = успіх, -1 = помилка
    static int writeKey(const char* path, EVP_PKEY* key);
};