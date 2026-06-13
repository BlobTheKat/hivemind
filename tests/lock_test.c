#include <a.h>
#include <stdio.h>
#include <string.h>

uint32_t x = 0;
void busy(){
	for(int i = 0; i < 16; i++){
		x = x^0x12345678;
		x ^= x>>7;
		x += x<<11;
		x *= 0xc0ffeebad;
	}
}

const int ITER = 1000000;
alignas(CACHE_LINE) lock_t sema4 = 0;
void* work(void* _){
	uint32_t i = 0;
	while(i < ITER){
		i++;
		lock_release(&sema4, 1);
	}
	return 0;
}

int main(){
	printf("\x1b[34m<a.h>\x1b[m\n");
	thread_t worker = thread_create(work, NULL, 0);
	uint32_t i = 0;
	while(i < ITER){
		lock_acquire(&sema4, 1);
		i++;
	}
	thread_join(worker);
	return 0;
}