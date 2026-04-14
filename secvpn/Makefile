CXX = g++
CXXFLAGS = -std=c++17
OPENSSL = $(shell pkg-config --cflags --libs openssl)

SRCS = libsecvpn.cpp pem_file_io.cpp ssl_context.cpp ssl_connection.cpp main_test.cpp

test:
	$(CXX) $(CXXFLAGS) $(SRCS) $(OPENSSL) -o test_all
	cd $(dir $(abspath $(lastword $(MAKEFILE_LIST)))) && ./test_all
	openssl verify -CAfile ca.crt server.crt
	openssl verify -CAfile ca.crt client.crt
