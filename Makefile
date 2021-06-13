CC=gcc
CFLAGS=-O3 main.c
TARGET=sha1 sha224 sha256 sha384 sha512

all: $(TARGET)

clean:
	rm $(TARGET)

%: %.c
	$(CC) $(CFLAGS) -D T_$@ $< -o $@

