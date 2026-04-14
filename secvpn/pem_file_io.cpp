#include "pem_file_io.h"
#include <openssl/bio.h>
#include <stdio.h>

X509* PemFileIO::readCert(const char* path) {
    FILE* f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "не вдалось відкрити %s\n", path);
        return nullptr;
    }

    X509* cert = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);

    if (cert == NULL) {
        fprintf(stderr, "не вдалось прочитати сертифікат з %s\n", path);
    }
    return cert;
}

EVP_PKEY* PemFileIO::readKey(const char* path) {
    FILE* f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "не вдалось відкрити %s\n", path);
        return nullptr;
    }

    EVP_PKEY* key = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);

    if (key == NULL) {
        fprintf(stderr, "не вдалось прочитати ключ з %s\n", path);
    }
    return key;
}

int PemFileIO::writeCert(const char* path, X509* cert) {
    FILE* f = fopen(path, "wb");
    if (f == NULL) {
        fprintf(stderr, "не вдалось відкрити %s\n", path);
        return -1;
    }

    if (PEM_write_X509(f, cert) != 1) {
        fprintf(stderr, "не вдалось записати сертифікат у %s\n", path);
        fclose(f);
        return -1;
    }

    fclose(f);
    return 0;
}

int PemFileIO::writeKey(const char* path, EVP_PKEY* key) {
    FILE* f = fopen(path, "wb");
    if (f == NULL) {
        fprintf(stderr, "не вдалось відкрити %s\n", path);
        return -1;
    }

    if (PEM_write_PrivateKey(f, key, NULL, NULL, 0, NULL, NULL) != 1) {
        fprintf(stderr, "не вдалось записати ключ у %s\n", path);
        fclose(f);
        return -1;
    }

    fclose(f);
    return 0;
}
