
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g

all: grain128a

init: CFLAGS += -DINIT
init: grain128a

pre: CFLAGS += -DPRE
pre: grain128a

grain128a: grain128a.c

clean:
	rm -f grain128a
