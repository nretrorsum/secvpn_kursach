// main_test.cpp — тест всієї C++ бібліотеки
#include "libsecvpn.h"
#include "ssl_context.h"
#include "ssl_connection.h"
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>

// === Тест 1: Генерація PKI ===
int test_pki() {
    printf("=== Тест 1: PKI ===\n");

    int rc = secvpn_generate_ca("TestCA", "ca.crt", "ca.key");
    if (rc != 0) {
        printf("FAIL: secvpn_generate_ca\n");
        return -1;
    }

    rc = secvpn_generate_cert("ca.crt", "ca.key",
                              "test-server", "server.crt", "server.key");
    if (rc != 0) {
        printf("FAIL: secvpn_generate_cert (server)\n");
        return -1;
    }

    rc = secvpn_generate_cert("ca.crt", "ca.key",
                              "test-client", "client.crt", "client.key");
    if (rc != 0) {
        printf("FAIL: secvpn_generate_cert (client)\n");
        return -1;
    }

    printf("PASS: PKI\n\n");
    return 0;
}

// === Тест 2: SslContext ===
int test_ssl_context() {
    printf("=== Тест 2: SslContext ===\n");

    SslContext server;
    if (!server.initServer()) {
        printf("FAIL: initServer\n");
        return -1;
    }
    if (!server.loadCert("server.crt")) {
        printf("FAIL: loadCert (server)\n");
        return -1;
    }
    if (!server.loadKey("server.key")) {
        printf("FAIL: loadKey (server)\n");
        return -1;
    }
    if (!server.loadCA("ca.crt")) {
        printf("FAIL: loadCA (server)\n");
        return -1;
    }

    SslContext client;
    if (!client.initClient()) {
        printf("FAIL: initClient\n");
        return -1;
    }
    if (!client.loadCert("client.crt")) {
        printf("FAIL: loadCert (client)\n");
        return -1;
    }
    if (!client.loadKey("client.key")) {
        printf("FAIL: loadKey (client)\n");
        return -1;
    }
    if (!client.loadCA("ca.crt")) {
        printf("FAIL: loadCA (client)\n");
        return -1;
    }

    if (server.raw() == nullptr || client.raw() == nullptr) {
        printf("FAIL: raw() повертає nullptr\n");
        return -1;
    }

    printf("PASS: SslContext\n\n");
    return 0;
}

// === Тест 3: SslConnection — повний mTLS handshake + read/write ===

struct ServerArgs {
    int fd;
    SslContext* ctx;
    int result;
};

void* server_thread(void* arg) {
    ServerArgs* args = (ServerArgs*)arg;
    args->result = -1;

    SSL* ssl = args->ctx->createSSL(args->fd);
    if (ssl == nullptr) {
        fprintf(stderr, "server: createSSL failed\n");
        return nullptr;
    }

    SslConnection conn(ssl);

    if (!conn.accept()) {
        fprintf(stderr, "server: accept failed\n");
        return nullptr;
    }

    // Читаємо повідомлення від клієнта
    char buf[256] = {0};
    int n = conn.read(buf, sizeof(buf) - 1);
    if (n <= 0) {
        fprintf(stderr, "server: read failed\n");
        return nullptr;
    }
    printf("  server отримав: \"%s\"\n", buf);

    // Відповідаємо
    const char* reply = "hello from server";
    if (conn.write(reply, strlen(reply)) <= 0) {
        fprintf(stderr, "server: write failed\n");
        return nullptr;
    }

    conn.shutdown();
    args->result = 0;
    return nullptr;
}

int test_ssl_connection() {
    printf("=== Тест 3: SslConnection (mTLS handshake + read/write) ===\n");

    // Створюємо пару з'єднаних сокетів
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        printf("FAIL: socketpair\n");
        return -1;
    }

    // Налаштовуємо контексти
    SslContext serverCtx;
    serverCtx.initServer();
    serverCtx.loadCert("server.crt");
    serverCtx.loadKey("server.key");
    serverCtx.loadCA("ca.crt");

    SslContext clientCtx;
    clientCtx.initClient();
    clientCtx.loadCert("client.crt");
    clientCtx.loadKey("client.key");
    clientCtx.loadCA("ca.crt");

    // Запускаємо сервер в окремому потоці
    ServerArgs sargs = {fds[0], &serverCtx, -1};
    pthread_t tid;
    pthread_create(&tid, nullptr, server_thread, &sargs);

    // Клієнтська сторона
    SSL* clientSsl = clientCtx.createSSL(fds[1]);
    if (clientSsl == nullptr) {
        printf("FAIL: client createSSL\n");
        close(fds[0]);
        close(fds[1]);
        return -1;
    }

    SslConnection clientConn(clientSsl);

    if (!clientConn.connect()) {
        printf("FAIL: client connect\n");
        pthread_join(tid, nullptr);
        close(fds[0]);
        close(fds[1]);
        return -1;
    }

    // Відправляємо повідомлення
    const char* msg = "hello from client";
    if (clientConn.write(msg, strlen(msg)) <= 0) {
        printf("FAIL: client write\n");
        pthread_join(tid, nullptr);
        return -1;
    }

    // Читаємо відповідь
    char buf[256] = {0};
    int n = clientConn.read(buf, sizeof(buf) - 1);
    if (n <= 0) {
        printf("FAIL: client read\n");
        pthread_join(tid, nullptr);
        return -1;
    }
    printf("  client отримав: \"%s\"\n", buf);

    clientConn.shutdown();
    pthread_join(tid, nullptr);

    close(fds[0]);
    close(fds[1]);

    if (sargs.result != 0) {
        printf("FAIL: серверний потік завершився з помилкою\n");
        return -1;
    }

    if (strcmp(buf, "hello from server") != 0) {
        printf("FAIL: неочікувана відповідь: \"%s\"\n", buf);
        return -1;
    }

    printf("PASS: SslConnection\n\n");
    return 0;
}

// === Тест 4: C API (для CGo) ===

struct CServerArgs {
    int fd;
    void* ctx;
    int result;
};

void* c_server_thread(void* arg) {
    CServerArgs* args = (CServerArgs*)arg;
    args->result = -1;

    void* conn = secvpn_ssl_new(args->ctx, args->fd);
    if (conn == NULL) {
        fprintf(stderr, "c_server: secvpn_ssl_new failed\n");
        return nullptr;
    }

    if (secvpn_ssl_accept(conn) != 0) {
        fprintf(stderr, "c_server: secvpn_ssl_accept failed\n");
        secvpn_ssl_close(conn);
        return nullptr;
    }

    char buf[256] = {0};
    int n = secvpn_ssl_read(conn, buf, sizeof(buf) - 1);
    if (n <= 0) {
        fprintf(stderr, "c_server: secvpn_ssl_read failed\n");
        secvpn_ssl_close(conn);
        return nullptr;
    }
    printf("  c_server отримав: \"%s\"\n", buf);

    const char* reply = "c-api reply";
    if (secvpn_ssl_write(conn, reply, strlen(reply)) <= 0) {
        fprintf(stderr, "c_server: secvpn_ssl_write failed\n");
        secvpn_ssl_close(conn);
        return nullptr;
    }

    secvpn_ssl_close(conn);
    args->result = 0;
    return nullptr;
}

int test_c_api() {
    printf("=== Тест 4: C API ===\n");

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        printf("FAIL: socketpair\n");
        return -1;
    }

    // Сервер через C API
    void* serverCtx = secvpn_ctx_new_server();
    if (serverCtx == NULL) { printf("FAIL: secvpn_ctx_new_server\n"); return -1; }
    if (secvpn_ctx_load_cert(serverCtx, "server.crt") != 0) { printf("FAIL: load_cert\n"); return -1; }
    if (secvpn_ctx_load_key(serverCtx, "server.key") != 0) { printf("FAIL: load_key\n"); return -1; }
    if (secvpn_ctx_load_ca(serverCtx, "ca.crt") != 0) { printf("FAIL: load_ca\n"); return -1; }

    // Клієнт через C API
    void* clientCtx = secvpn_ctx_new_client();
    if (clientCtx == NULL) { printf("FAIL: secvpn_ctx_new_client\n"); return -1; }
    if (secvpn_ctx_load_cert(clientCtx, "client.crt") != 0) { printf("FAIL: load_cert\n"); return -1; }
    if (secvpn_ctx_load_key(clientCtx, "client.key") != 0) { printf("FAIL: load_key\n"); return -1; }
    if (secvpn_ctx_load_ca(clientCtx, "ca.crt") != 0) { printf("FAIL: load_ca\n"); return -1; }

    // Сервер у потоці
    CServerArgs sargs = {fds[0], serverCtx, -1};
    pthread_t tid;
    pthread_create(&tid, nullptr, c_server_thread, &sargs);

    // Клієнт
    void* clientConn = secvpn_ssl_new(clientCtx, fds[1]);
    if (clientConn == NULL) { printf("FAIL: secvpn_ssl_new\n"); return -1; }

    if (secvpn_ssl_connect(clientConn) != 0) {
        printf("FAIL: secvpn_ssl_connect\n");
        pthread_join(tid, nullptr);
        return -1;
    }

    const char* msg = "c-api hello";
    if (secvpn_ssl_write(clientConn, msg, strlen(msg)) <= 0) {
        printf("FAIL: secvpn_ssl_write\n");
        pthread_join(tid, nullptr);
        return -1;
    }

    char buf[256] = {0};
    int n = secvpn_ssl_read(clientConn, buf, sizeof(buf) - 1);
    if (n <= 0) {
        printf("FAIL: secvpn_ssl_read\n");
        pthread_join(tid, nullptr);
        return -1;
    }
    printf("  c_client отримав: \"%s\"\n", buf);

    secvpn_ssl_close(clientConn);
    pthread_join(tid, nullptr);

    close(fds[0]);
    close(fds[1]);

    secvpn_ctx_free(serverCtx);
    secvpn_ctx_free(clientCtx);

    if (sargs.result != 0) {
        printf("FAIL: серверний потік C API\n");
        return -1;
    }

    if (strcmp(buf, "c-api reply") != 0) {
        printf("FAIL: неочікувана відповідь: \"%s\"\n", buf);
        return -1;
    }

    printf("PASS: C API\n\n");
    return 0;
}

int main() {
    int failures = 0;

    if (test_pki() != 0) failures++;
    if (test_ssl_context() != 0) failures++;
    if (test_ssl_connection() != 0) failures++;
    if (test_c_api() != 0) failures++;

    printf("=============================\n");
    if (failures == 0) {
        printf("Всі тести пройшли!\n");
    } else {
        printf("%d тест(ів) провалилось\n", failures);
    }

    return failures;
}
