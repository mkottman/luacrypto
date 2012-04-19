all: *.lua
	cp ../src/.libs/libluacrypto.so.0.0.0 crypto.so
	./run-tests

clean-local:
	rm -f crypto.so
	rm -f *.pem
