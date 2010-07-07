SHELL	= /bin/sh

DIET	= diet -Os
CC	= $(DIET) gcc
CFLAGS	= -Os -Wall -W
LDFLAGS	= -s 
LIBS	=

ALL = minicron

all: $(ALL)

%.o: %.c
	$(CC) $(CFLAGS) -c $^

clean:
	rm -f a.out *.o *~ $(ALL) *.tar.bz2 *.tar.gz Z*

