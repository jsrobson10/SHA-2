CC=gcc
CFLAGS=-Werror -Wall -O3 main.c
TARGET=sha1 sha224 sha256 sha384 sha512
DEPS=main.c

all: $(TARGET)

clean:
	rm $(TARGET)

%: %.c $(DEPS)
	$(CC) $(CFLAGS) -D T_$@ $< -o $@

