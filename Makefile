SHELL	= /bin/sh

DIET	= diet -Os
CC	= $(DIET) gcc
CFLAGS	= -pipe -Os -Wall -W
LDFLAGS	= -s 
LIBS	= -lowfat

ALL = minicron

all: $(ALL)

%.o: %.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c $^
	
minicron: minicron.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f a.out *.o *~ $(ALL) *.tar.bz2 *.tar.gz Z*

