SHELL	= /bin/sh

DIET	= diet -Os
CC	= $(DIET) gcc
CFLAGS	= -Os -Wall -W
LDFLAGS	= -s 
LIBS	= -lowfat

ALL = minicron

all: $(ALL)

%.o: %.c
	$(CC) $(CFLAGS) -c $^
	
minicron: minicron.c
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f a.out *.o *~ $(ALL) *.tar.bz2 *.tar.gz Z*

