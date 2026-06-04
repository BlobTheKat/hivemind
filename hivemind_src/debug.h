#pragma once
#include "internals.c"

deprecate("Debug")
static void check_send(struct _hivemind_remote* state){
	if(!state->unsent_i)
		assert(state->send_order_end == &state->send_order_start);
	size_t lo = state->send_seq_lo-ring_buffer_size(&state->send_queue)/sizeof(struct _send_packet**);
	bool f = !state->send_seq_lo&&!state->send_seq_hi;
	for(size_t j = 0; j < state->unsent_i; j += sizeof(struct _send_packet**)){
		struct _send_packet** v2;
		ring_buffer_get(&state->send_queue, j, &v2, sizeof(v2), true);
		if(v2) assert(lo == lseqof(*v2));
		lo++;
	}
}

deprecate("Debug")
static bool validate_ack(struct _hivemind_remote* state, uint64_t seq){
	size_t idx = (seq-state->recv_seq_lo);
	if(idx > SIZE_MAX/sizeof(sfat_pointer_t)) return true;
	size_t sz = ring_buffer_size(&state->recv_queue);
	idx *= sizeof(sfat_pointer_t);
	if(idx >= sz) return false;
	sfat_pointer_t m;
	ring_buffer_get(&state->recv_queue, idx, &m, sizeof(m), true);
	return !!sfat_get(m);
}

static array_buffer_t logs;
#define logf(...) do{ \
	char* __out; int __len = asprintf(&__out, __VA_ARGS__); \
	array_buffer_push(&logs, __out, (size_t)__len); free(__out); \
}while(0);
static void __uncork_logs(){
	fwrite(array_buffer_data(&logs), array_buffer_size(&logs), 1, stdout);
	array_buffer_clear(&logs);
}
static void (*uncork_logs)() = __uncork_logs;