# COMPILE FLAGS
CFLAGS = -Wall -Werror -O2

all: elg_client_demo 

elg_client_demo: sky_crypt.o sky_protocol_client_1.o mauth.o hmac.o aes.o sky_util.o
	gcc $(CFLAGS) -o bin/elg_client_demo bin/sky_crypt.o bin/mauth.o bin/hmac.o \
	bin/aes.o bin/sky_protocol_client_1.o bin/sky_util.o src/skyhook_elg_client_demo.c -Ielg_lib

mauth.o: elg_lib/mauth.c
	gcc $(CFLAGS) -c elg_lib/mauth.c -o bin/mauth.o -Iinc -IHMAC

hmac.o: HMAC/hmac256.c
	gcc $(CFLAGS) -c HMAC/hmac256.c -o bin/hmac.o

sky_protocol_client_1.o: elg_lib/sky_protocol_client_1.c
	gcc $(CFLAGS) -c elg_lib/sky_protocol_client_1.c -o bin/sky_protocol_client_1.o 

sky_util.o: elg_lib/sky_util.c
	gcc $(CFLAGS) -c elg_lib/sky_util.c -o bin/sky_util.o 

sky_crypt.o: elg_lib/sky_crypt.c
	gcc $(CFLAGS) -c elg_lib/sky_crypt.c -o bin/sky_crypt.o -Itiny-AES128-C

aes.o: tiny-AES128-C/aes.c
	gcc $(CFLAGS) -c tiny-AES128-C/aes.c -o bin/aes.o

clean:
	rm -f bin/*
