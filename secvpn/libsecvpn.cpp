#include "libsecvpn.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <stdio.h>

int secvpn_generate_ca(const char *cn, const char *out_cert, const char *out_key) {
    // Генеруємо пару ключів
    // EVP_PKEY — універсальний контейнер для будь-якого ключа
    EVP_PKEY *pkey = EVP_RSA_gen(4096);
    if (pkey == NULL) {
        fprintf(stderr, "помилка генерації ключа\n");
        return -1;
    }

    // ЧАСТИНА Б — створюємо порожній сертифікат
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

    // ЧАСТИНА В — встановлюємо ім'я (CN)
    X509_NAME *name = X509_get_subject_name(cert);

    // CN — Common Name, наприклад "MyVPN-CA"
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
        "critical,CA:TRUE"  // ← ось це позначає CA
    );
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);

    // ЧАСТИНА Г — підписуємо сертифікат своїм ключем
    // SHA256 — алгоритм хешування для підпису
    if (X509_sign(cert, pkey, EVP_sha256()) == 0) {
        fprintf(stderr, "помилка підпису\n");
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return -1;
    }

    // Зберігаємо сертифікат у файл .crt
    FILE *f_cert = fopen(out_cert, "wb");
    if (f_cert == NULL) {
        fprintf(stderr, "не вдалось відкрити файл %s\n", out_cert);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return -1;
    }
    PEM_write_X509(f_cert, cert);
    fclose(f_cert);

    // Зберігаємо приватний ключ у файл .key
    FILE *f_key = fopen(out_key, "wb");
    if (f_key == NULL) {
        fprintf(stderr, "не вдалось відкрити файл %s\n", out_key);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return -1;
    }
    PEM_write_PrivateKey(f_key, pkey,
        NULL, NULL, 0, NULL, NULL); // без пароля
    fclose(f_key);

    // Звільняємо пам'ять — C не має GC
    X509_free(cert);
    EVP_PKEY_free(pkey);

    printf("CA створено: %s, %s\n", out_cert, out_key);
    return 0;  // успіх
}

int secvpn_generate_cert(const char *ca_cert_path, const char *ca_key_path,
                         const char *cn,
                         const char *out_cert, const char *out_key) {

    // === Крок 1: Завантажуємо CA сертифікат ===
    FILE *file_ca_cert = fopen(ca_cert_path, "rb");
    if (file_ca_cert == NULL) {
        fprintf(stderr, "не вдалось відкрити %s\n", ca_cert_path);
        return -1;
    }
    char ca_cert_buffer[4096];
    fread(ca_cert_buffer, 1, sizeof(ca_cert_buffer) - 1, file_ca_cert);
    ca_cert_buffer[sizeof(ca_cert_buffer) - 1] = '\0';
    fclose(file_ca_cert);

    BIO *bio1 = BIO_new_mem_buf(ca_cert_buffer, -1);
    X509 *ca_cert = PEM_read_bio_X509(bio1, NULL, NULL, NULL);
    BIO_free(bio1);

    if (ca_cert == NULL) {
        fprintf(stderr, "не вдалось прочитати CA сертифікат\n");
        return -1;
    }

    // === Крок 1: Завантажуємо CA ключ ===
    FILE *file_ca_key = fopen(ca_key_path, "rb");
    if (file_ca_key == NULL) {
        fprintf(stderr, "не вдалось відкрити %s\n", ca_key_path);
        X509_free(ca_cert);
        return -1;
    }
    char ca_key_buffer[4096];
    fread(ca_key_buffer, 1, sizeof(ca_key_buffer) - 1, file_ca_key);
    ca_key_buffer[sizeof(ca_key_buffer) - 1] = '\0';
    fclose(file_ca_key);

    BIO *bio2 = BIO_new_mem_buf(ca_key_buffer, -1);
    EVP_PKEY *ca_key = PEM_read_bio_PrivateKey(bio2, NULL, NULL, NULL);
    BIO_free(bio2);

    if (ca_key == NULL) {
        fprintf(stderr, "не вдалось прочитати CA ключ\n");
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

    X509_set_pubkey(cert, private_key);  // ✅ виправлено

    // === Крок 4: Встановлюємо CN ===
    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN",
        MBSTRING_ASC,
        (const unsigned char *)cn,
        -1, -1, 0);
    X509_set_subject_name(cert, name);

    // === Крок 5: Issuer = CA ===
    // Хто видав цей сертифікат — наш CA
    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));

    // === Крок 6: Підписуємо ключем CA ===
    // Головна різниця від generate_ca — тут підписує CA а не сам себе
    if (X509_sign(cert, ca_key, EVP_sha256()) == 0) {
        fprintf(stderr, "не вдалось підписати сертифікат\n");
        X509_free(cert);
        EVP_PKEY_free(private_key);
        X509_free(ca_cert);
        EVP_PKEY_free(ca_key);
        return -1;
    }

    // === Крок 7: Зберігаємо сертифікат у файл ===
    FILE *f_cert = fopen(out_cert, "wb");
    if (f_cert == NULL) {
        fprintf(stderr, "не вдалось відкрити %s\n", out_cert);
        X509_free(cert);
        EVP_PKEY_free(private_key);
        X509_free(ca_cert);
        EVP_PKEY_free(ca_key);
        return -1;
    }
    PEM_write_X509(f_cert, cert);
    fclose(f_cert);

    // === Крок 8: Зберігаємо ключ у файл ===
    FILE *f_key = fopen(out_key, "wb");
    if (f_key == NULL) {
        fprintf(stderr, "не вдалось відкрити %s\n", out_key);
        X509_free(cert);
        EVP_PKEY_free(private_key);
        X509_free(ca_cert);
        EVP_PKEY_free(ca_key);
        return -1;
    }
    PEM_write_PrivateKey(f_key, private_key, NULL, NULL, 0, NULL, NULL);
    fclose(f_key);

    // === Звільняємо всю пам'ять ===
    X509_free(cert);
    EVP_PKEY_free(private_key);
    X509_free(ca_cert);
    EVP_PKEY_free(ca_key);

    printf("сертифікат створено: %s, %s\n", out_cert, out_key);
    return 0;
}