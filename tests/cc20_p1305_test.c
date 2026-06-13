// clang -fsanitize=undefined -fsanitize=address -O3 cc20_p1305_test.c -o test.out -lsodium && ./test.out; rm test.out
// clang -DPOLY1305_TESTS=1000000 -DCHACHA20_TESTS=1000000 -O3 cc20_p1305_test.c -o test.out -lsodium && ./test.out; rm test.out

#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <sodium.h>

#define WIDTH 16

void hexdump(const void *data, size_t len) {
	const uint8_t *p = (const uint8_t *)data;

	for (size_t i = 0; i < len; i += WIDTH) {
		/* Hex bytes */
		for (size_t j = 0; j < WIDTH; j++) {
			if (i + j < len)
				printf((j&3)==3?"%02x   ":"%02x ", p[i + j]);
		}
		printf("\n");
	}
}

#include <chacha20poly1305.h>
#include <time.h>


#ifndef POLY1305_TESTS
#define POLY1305_TESTS 1000000
#endif
#ifndef CHACHA20_TESTS
#define CHACHA20_TESTS 1000000
#endif

void* work(void* _){
	int failed = 0;
#if POLY1305_TESTS > 0
	for(int i = 0; i < POLY1305_TESTS; i++){
		_Alignas(4) unsigned char key[32], tag[16], tag2[16];
		int msglen = (rand()&0xFF)+1;
		unsigned char msg[msglen];
		randombytes_buf(msg, msglen);
		randombytes_buf(key, 32);
		crypto_onetimeauth(tag, msg, msglen, key);
		Poly1305(msg, msglen, key, tag2);
		if(memcmp(tag, tag2, 16)){
			printf("\nKey=\n");
			hexdump(key, 32);
			printf("\nTag (sodium)=\n");
			hexdump(tag, 16);
			printf("\nTag (chacha20poly1305.h)=\n");
			hexdump(tag2, 16);
			failed++;
		}
	}
	if(failed) printf("\x1b[31m%d/%d Poly1305 tests failed\x1b[m\n", failed, POLY1305_TESTS);
	else printf("\x1b[32mAll %d Poly1305 tests passed\x1b[m\n", POLY1305_TESTS);
	failed = 0;
#endif
#if CHACHA20_TESTS > 0
	for(int i = 0; i < CHACHA20_TESTS; i++){
		uint32_t state[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}; // "expand 32-byte k"
		unsigned char key[32], nonce[8];
		randombytes_buf(state+4, 48);
		for(int i = 0; i < 32; i++) key[i] = state[(i>>2)+4]>>(i&3)*8;
		for(int i = 0; i < 8; i++) nonce[i] = state[(i>>2)+14]>>(i&3)*8;
		uint8_t out[64] = {0}, out2[64] = {0};
		crypto_stream_chacha20_xor_ic(out, out, 64, nonce, (uint64_t)state[12]|(uint64_t)state[13]<<32, key);
		ChaCha20_block_xor(state, out2, 1);
		if(memcmp(out, out2, 64)){
			printf("\nState=\n");
			hexdump((uint8_t*)state, 64);
			printf("\nBlock (sodium)=\n");
			hexdump(out, 64);
			printf("\nBlock (chacha20poly1305.h)=\n");
			hexdump(out2, 64);
			failed++;
		}
	}
	if(failed) printf("\x1b[31m%d/%d chacha20 tests failed\x1b[m\n", failed, CHACHA20_TESTS);
	else printf("\x1b[32mAll %d chacha20 tests passed\x1b[m\n", CHACHA20_TESTS);
	failed = 0;
#endif
	return 0;
}

#ifndef THREADS
#define THREADS 1
#endif
#if THREADS > 1
#include <a.h>
#endif

int main(){
	if(sodium_init() < 0) return -1;
	srand(time(0));
	#if THREADS > 1
	thread_t thrs[THREADS-1];
	for(int i = 0; i < THREADS-1; i++){
		thrs[i] = thread_create(work, 0, 0);
	}
	#endif
	work(0);
	#if THREADS > 1
	for(int i = 0; i < THREADS-1; i++){
		thread_join(thrs[i]);
	}
	#endif
}