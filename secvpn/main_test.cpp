// main_test.cpp
#include "libsecvpn.h"
#include <stdio.h>

int main() {
    int result = secvpn_generate_ca(
        "MyVPN-CA",   // CN
        "ca.crt",     // куди зберегти сертифікат
        "ca.key"      // куди зберегти ключ
    );

    if (result == 0) {
        printf("Успіх!\n");
    } else {
        printf("Помилка!\n");
    }

    int server_cert = secvpn_generate_cert("ca.crt", "ca.key",
                        "vpnd-server",
                        "server.crt", "server.key");

    int client_cert = secvpn_generate_cert("ca.crt", "ca.key",
                        "vpnctl-client",
                        "client.crt", "client.key");

    return 0;
}