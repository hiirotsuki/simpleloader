CC := i686-w64-mingw32-gcc
CFLAGS_MANDATORY = -mwindows -nostartfiles
CFLAGS := -ansi -pedantic -Wall -Wextra

all: loader

loader: loader.c
	$(CC) $(CFLAGS_MANDATORY) $(CFLAGS) -I. $? -o $@ $(LDFLAGS)

clean:
	rm -f loader.exe *.o

.PHONY: clean
