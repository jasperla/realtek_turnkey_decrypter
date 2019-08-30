CFLAGS ?= -I/usr/local/opt/openssl/include
LDFLAGS ?= -L/usr/local/opt/openssl/lib
LIBS ?= -lcrypto
SOURCES = decrypt.c Base64Decode.c
OBJECTS =${SOURCES:.c=.o}

decrypt: ${OBJECTS}
	${CC} ${LDFLAGS} ${LIBS} ${OBJECTS} -o $@

.c.o:
	${CC} ${CFLAGS} -c $< -o $@

all: decrypt

.PHONY: clean

clean:
	rm -f *.o *.core decrypt
