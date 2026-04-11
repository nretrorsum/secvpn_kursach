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
#ifdef __cplusplus
}
#endif

#endif