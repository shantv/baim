#
SHLIB_CFLAGS =		-fpic 
SHLIB_LD =		gcc -shared
SHLIB_SUFFIX =		.so
CC = gcc

CFLAGS = -O -g -I../../include $(SHLIB_CFLAGS)

OBJS = baim.o

default:
	(cd ..;$(MAKE))

all: baim$(SHLIB_SUFFIX)

baim.o: baim.c
	$(CC) $(CFLAGS) -I../../include $(INCLUDES) -c baim.c

baim$(SHLIB_SUFFIX): $(OBJS) baim.c 
	$(SHLIB_LD) $(OBJS) $(SHLIB_CFLAGS) -o baim$(SHLIB_SUFFIX)
	./ask

clean::
	rm -f *~ *.o *.so *.a *.dll

clean::
	rm -f *~ *.o *.so *.a *.dll

distclean: clean
	rm -f *~ *.o *.so *.a *.dll

