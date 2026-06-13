#include <a.h>
#include <stdio.h>
#include <string.h>

thread_local volatile uint32_t __no_opt = 0;
void busy(){
	return;
	uint32_t x = __no_opt;
	for(int i = 0; i < 16; i++){
		x = x^0x12345678;
		x ^= x>>7;
		x += x<<11;
		x *= 0xdeadbeef;
	}
	__no_opt = x;
}

const int ITER = 1000000;
alignas(CACHE_LINE) atomic(uint32_t) done = 0;
void* work(void* _){
	uint64_t start = local_now();
	uint32_t i = 0;
	while(i < ITER){
		busy();
		atomic_store_explicit(&done, i+1, memory_order_release);
		atomic_wake_condition(&done, 1);
		i += 2;
		atomic_wait_until(&done, atomic_load_explicit(&done, memory_order_acquire) == i);
	}
	atomic_store_explicit(&done, i, memory_order_release);
	atomic_wake(&done, 1);
	printf("%d ping-pong increment (thrds: 2): \x1b[33m%.2fms\x1b[m\n", ITER, (double)(local_now()-start)/MILLISECOND_US);
	return 0;
}

int main(){
	printf("\x1b[34m<a.h>\x1b[m\n");
	thread_t worker = thread_create(work, NULL, 0);
	uint32_t i = 1;
	while(i < ITER){
		atomic_wait_until(&done, atomic_load_explicit(&done, memory_order_acquire) == i);
		busy();
		atomic_store_explicit(&done, i+1, memory_order_release);
		atomic_wake_condition(&done, 1);
		i += 2;
	}
	thread_join(worker);
	return 0;
}