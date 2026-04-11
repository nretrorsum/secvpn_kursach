CXX = g++
OPENSSL = $(shell pkg-config --cflags --libs openssl)

test:
	$(CXX) libsecvpn.cpp main_test.cpp $(OPENSSL) -o test_ca
	./test_ca
	openssl verify -CAfile ca.crt server.crt
	openssl verify -CAfile ca.crt client.crt