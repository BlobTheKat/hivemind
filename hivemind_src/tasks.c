#include "save.c"
#ifndef _WIN32
	#include <signal.h>
#endif

// THREAD STACK LINKED LIST!!!
struct _hivemind_thread{
	atomic(struct _hivemind_thread*) next, *prevp;
	// Hazard pointer for GC and UDP reads
	atomic(void*) hazard;
};
struct{
	x_event_queue_t queue;
	lock_t threads_lock;
	uint32_t threads_max, threads_cur;
	atomic(struct _hivemind_remote*) undrained;
	atomic(struct _hivemind_remote*) unsent_ack;
	atomic(hivemind_server_t*) read_help_requested;
	atomic(uint64_t) last_gc;
	atomic(hivemind_server_t*) servers;
	atomic(struct _hivemind_thread*) threads;
} _hivemind_meta = {
	.threads_lock = 1,
	.undrained = (struct _hivemind_remote*)1,
	.unsent_ack = (struct _hivemind_remote*)1
};
static_assert(alignof(thread_t) <= alignof(max_align_t));
// Hazard slots in this implementation follow a thread-to-thread linked list (it's all allocated in the stack) protected by threads_lock

struct _hivemind_danger_entry{ void* what; union x_userdata_t data; };
// caller needs to have `test` hazarded order-before the remove it is expected to be protected against

// Acquire semantics
static inline void _hazard_wait(void* target){
	struct _hivemind_thread* t = atomic_load_explicit(&_hivemind_meta.threads, memory_order_acquire);
	while(t){
		retry: {}
		void* h = atomic_load_explicit(&t->hazard, memory_order_relaxed);
		if(h == target || h == (void*)-1ull){
			thread_sleep(1); // Very strong yield
			goto retry;
		}
		t = atomic_load_explicit(&t->next, memory_order_acquire);
	}
}

#define GC_FREQ (3600*SECOND_US)

static void _remove_unused(hivemind_server_t* s, uint64_t t){
	array_buffer_t candidates = {0};
	uint64_t c = s->state_lifetime;
	shared_lock_acquire(&s->state_lock);
	size_t buckets = (1<<s->buckets_exp&-2ull)>>1;
	struct _hivemind_remote** l = s->remote_buckets;
	if(buckets < 2) l = (struct _hivemind_remote**) &s->remote_buckets;
	for(size_t b = 0; b < buckets; b++){
		struct _hivemind_remote* state = s->remote_buckets[b];
		while(state){
			uint64_t r = atomic_load_explicit(&state->recv_last_used, memory_order_relaxed);
			uint64_t s = atomic_load_explicit(&state->send_last_used, memory_order_relaxed);
			if(r && s && (r-t+1)>>1 > c && s-t > c){
				array_buffer_push(&candidates, &state, sizeof(state));
			}
			assert(state != state->next);
			state = state->next;
		}
	}
	if(!array_buffer_size(&candidates)){
		shared_lock_release(&s->state_lock);
		return;
	}
	shared_lock_upgrade(&s->state_lock);
	array_iterator_t it = array_buffer_iterator(&candidates, 0, -1ull);
	struct _hivemind_remote* state;
	while(array_iterator_next(&it, &state, sizeof(state))){
		uint64_t r = _time_lock_acq(&state->recv_last_used);
		uint64_t s = _time_lock_acq(&state->send_last_used);
		t = _hivemind_internal_clock();
		if(state->send_unlocked_ref || state->recv_unlocked_ref || state->undrained_next || state->unsent_ack_next || (r-t+1)>>1 <= c || s-t <= c){
			_time_lock_rel(&state->recv_last_used, r);
			_time_lock_rel(&state->send_last_used, s);
			continue;
		}
		// FREE!!!
		_hivemind_remote_cleanup_recv(state);
		_hivemind_remote_cleanup_send(state);
		*state->prevp = state->next;
		if(state->next)
			state->next->prevp = &state->next;
		free(state);
	}
	array_buffer_destroy(&candidates);
	exclusive_lock_release(&s->state_lock);
}

static size_t _hivemind_send_packet(struct _hivemind_remote* state, struct _send_packet* packet, uint64_t now, size_t i){
	//printf("send %zu i=%zu\n", lseqof(packet), i);
	unsigned len = lenof(packet);
	bool send_success = x_udp_send(state->handle, (remote_t){state->addr, state->port, 0, 0}, (char*)packet->payload, len);
	soft_assert(send_success);
	struct _send_packet** rpacket = state->send_order_end;
	*rpacket = packet; state->send_order_end = &packet->next;
	packet->next = 0; packet->time_lo = now;
	ring_buffer_set(&state->send_queue, i, &rpacket, sizeof(rpacket), true);
	return len+48;
}

static void _drain_writes(struct _hivemind_remote* state, uint64_t now){
	if unlikely((state->rtt_gate_lo&5)==4){
		// network partition
		uint32_t rtt_gate = (uint32_t)state->rtt_gate_lo|(uint32_t)state->rtt_gate_hi<<16;
		if(rtt_gate < 256){
			// Timer expired, send a probe packet
			uint8_t packet[40];
			uint32_t* knonce = (uint32_t*)(packet+20);
			uint32_t poly_key[8];
			_keyless_sig(state->server, &state->remote, knonce, poly_key, 0, 0);
			uint32_t opts = 0;
			Poly1305((uint8_t*)&opts, 4, (uint8_t*)poly_key, packet);
			*(uint32_t*)(packet+16) = knonce[0]; knonce[0] = opts;
			bool send_success = x_udp_send(state->handle, state->remote, (char*)packet, 40);
			soft_assert(send_success);
			unsigned gen = rtt_gate>>3&31;
			if(gen<24) gen++;
			rtt_gate = 4 | gen<<3 | ((1u<<(gen>>1))-1)<<8;
		}else rtt_gate -= 256;
		state->rtt_gate_lo = rtt_gate; state->rtt_gate_hi = rtt_gate>>16;
		return;
	}
	float left = now-state->send_window;
	if(left > SEND_BURST){
		left = SEND_BURST;
		state->send_window = now-SEND_BURST;
	}
	if(left <= 0) return;
	size_t sendable_now = /*floor*/ (size_t)(left / state->us_per_byte), sent = 0;
	if(!sendable_now) return;

	// find unacked
	struct _send_packet **rpacket = &state->send_order_start, *packet = *rpacket;
	uint64_t cutoff = (uint64_t)(state->avg_latency*2.);
	if(cutoff < SEND_TICK*2) cutoff = SEND_TICK*2;
	cutoff = (now - cutoff) << 16;
	size_t sz = ring_buffer_size(&state->send_queue);
	if(packet) do{
		if((int64_t)((packet->time_lo<<16) - cutoff) >= 0) break;
		if(packet->resent++ == 15){
			// 16 failed attempts, network partition? remote restarted? we don't know. Go into probe mode
			state->rtt_gate_hi = 0; state->rtt_gate_lo = 4;
			return;
		}
		// Resent lost packet
		struct _send_packet* next = packet->next;
		if(!(*rpacket = next)){
			state->send_order_end = rpacket;
		}else{
			size_t i2 = sz + (lseqof(next) - state->send_seq_lo) * sizeof(struct _send_packet**);
			ring_buffer_set(&state->send_queue, i2, &rpacket, sizeof(rpacket), true);
			packet->next = 0;
		}
		if(packet == state->send_order_start)
			state->send_order_start = next;

		size_t i = sz + (lseqof(packet) - state->send_seq_lo) * sizeof(struct _send_packet**);
		sent += _hivemind_send_packet(state, packet, now, i);
		//if(DEBUG) check_send(state);
		packet = packet->next;
	}while(packet && sent < sendable_now);
	// drain unsent
	if(sent < sendable_now){
		uint32_t chacha_in[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}; // "expand 32-byte k"
		memcpy(chacha_in+4, state->send_key, 32);
		size_t df = (ring_buffer_size(&state->send_queue)-state->unsent_i) / sizeof(struct _send_packet*);
		uint64_t seq_lo = state->send_seq_lo - df; uint32_t seq_hi = state->send_seq_hi - (seq_lo > state->send_seq_lo);
		ring_iterator_t it = ring_buffer_iterator(&state->send_queue, state->unsent_i, -1ull);
		do{
			if unlikely(state->unsent_i >= 0x7FFFFF00*sizeof(struct _send_packet*)) break;
			if(!it.remaining) end: {
				// Don't measure throughput for a gap where we're not even trying
				state->rtt_gate_lo = 0;
				state->rtt_gate_hi = 0;
				break;
			}
			struct _send_packet *packet;
			ring_iterator_next(&it, &packet, sizeof(packet), true);
			if(!packet) goto end;
			chacha_in[13] = (uint32_t)seq_lo;
			chacha_in[14] = (uint32_t)(seq_lo>>32);
			chacha_in[15] = seq_hi;
			encrypt_packet(chacha_in, packet);
			sent += _hivemind_send_packet(state, packet, now, state->unsent_i);
			if(!state->send_order_start) state->send_order_start = packet;
			state->unsent_i += sizeof(struct _send_packet*);
			//if(DEBUG) check_send(state);
			if(!++seq_lo) seq_hi++;
		}while(sent < sendable_now);
	}
	state->send_window += (uint64_t)((double)sent*(double)state->us_per_byte);
}

static inline void _update_throughput(struct _hivemind_remote* state, struct _send_packet* p, float ithr, float a){
	ithr /= (1 + fast_exp2f(state->growth)) * (lenof(p)+48);
	state->us_per_byte += (ithr-state->us_per_byte)*a;
	assert(state->us_per_byte > 0.f);
}

static void _hivemind_ackd(struct _hivemind_remote* state, uint8_t* packet, unsigned plen, uint64_t t0){
	uint64_t lo0 = state->send_seq_lo; uint32_t hi = state->send_seq_hi;
	size_t sz = ring_buffer_size(&state->send_queue);
	uint64_t lo2 = lo0 - sz/sizeof(struct _send_packet**);
	if(lo2>lo0){ hi--; }; lo0 = lo2;
	_resolve_seq(&lo0, &hi, le32toh(*(uint32_t*)(packet+16)));

	size_t i0 = (lo0 - lo2) * sizeof(struct _send_packet**);
	lo2 += state->unsent_i/sizeof(struct _send_packet**);
	if(i0 >= state->unsent_i+(128*sizeof(struct _send_packet**))) return;
	//printf("ack'd [%u,%llu]", hi, lo0);

	union{
		uint32_t words[16];
		uint8_t bytes[64];
	} chacha = {.words = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}}; // "expand 32-byte k"
	memcpy(chacha.words+4, state->send_key, 32);
	chacha.words[12] = 0xFFFFFFFE; chacha.words[13] = (uint32_t)lo0;
	chacha.words[14] = (uint32_t)(lo0>>32); chacha.words[15] = hi;
	ChaCha20_block(chacha.words);
	Poly1305(packet+20, plen-20, chacha.bytes, chacha.bytes+32);
	uint32_t *dtag = (uint32_t*)(chacha.bytes+32), *ptag = (uint32_t*)packet;
	if(memcmp16(dtag, ptag))
		return; // poly failed

	uint8_t* packet_end = packet+plen;
	packet += 20;
	if(plen > 20) t0 -= le32toh(*(uint32_t*)(packet_end-4))>>8;
	uint32_t x = 0;
	//if(DEBUG) check_send(state);

	for(;;){
		int8_t delta = (int8_t)(uint8_t)x;
		//printf(packet == packet_end ? "+%d\n" : "+%d", delta);
		size_t i = i0 + (size_t)(ssize_t)delta * sizeof(struct _send_packet**);
		uint64_t t = t0+(x>>8), lo = lo0+(uint64_t)(int64_t)delta;
		if(i >= state->unsent_i) next: {
			if(packet < packet_end){
				x = le32toh(*(uint32_t*)packet);
				packet += 4;
				continue;
			}else break;
		}
		struct _send_packet** spacket;
		ring_buffer_get(&state->send_queue, i, &spacket, sizeof(spacket), true);
		if(!spacket) goto next;

		struct _send_packet* p = *spacket, *next = p->next;
		if(!(*spacket = next)){
			state->send_order_end = spacket;
		}else{
			size_t i2 = sz + (lseqof(next)-state->send_seq_lo) * sizeof(struct _send_packet**);
			ring_buffer_set(&state->send_queue, i2, &spacket, sizeof(spacket), true);
		}
		if(state->send_order_start == p) state->send_order_start = next;
		assert((lo&0xFFFFFFFFFFFF) == lseqof(p));

		if(!p->resent){
			// ADJUSTMENTS HERE
			float i_minlat = 1.f / state->min_latency;
			if(i_minlat > 1.f/SEND_TICK) i_minlat = 1.f/SEND_TICK;
			float ipprt = state->us_per_byte * (lenof(p)+48) * i_minlat;
			if(ipprt > 1.f) ipprt = 1.f;
			float lat = (int64_t)((t - p->time_lo)<<16)>>16;
			float dt = (float)(t - state->min_latency_when) * i_minlat * .03125f;
			if(lat < state->min_latency * (dt < 1.f ? 1.f : dt)){
				state->min_latency = lat;
				state->min_latency_when = t;
			}
			assert(lat >= 0.f);
			uint32_t rtt_gate = (uint32_t)state->rtt_gate_lo|(uint32_t)state->rtt_gate_hi<<16;
			float ithr = (int64_t)((t-state->last_ack)<<16)>>16;
			if(ithr > 0.f) state->last_ack = t;
			else ithr = 0.f;
			if(rtt_gate != 2){
				if(rtt_gate == 8){
					rtt_gate = (uint32_t)lo2<<1|1;
					state->rtt_gate_lo = rtt_gate;
					state->rtt_gate_hi = rtt_gate>>16;
					state->avg_latency = lat;
					goto adj_end;
				}else if((uint32_t)(lo<<1|1) == rtt_gate){
					state->rtt_gate_lo = 2;
					state->rtt_gate_hi = 0;
				}else{
					_update_throughput(state, p, ithr, ipprt*.25f);
					state->avg_latency += (lat - state->avg_latency)*ipprt;
					if unlikely((rtt_gate&5)==4){
						// Partition restored
						state->rtt_gate_hi = 0;
						state->rtt_gate_lo = state->unsent_i < ring_buffer_size(&state->send_queue) ? 8 : 0;
					}
					goto adj_end;
				}
			}
			_update_throughput(state, p, ithr, ipprt*.25f);
			lat = (lat - state->avg_latency) * ipprt;
			state->avg_latency += lat*.125f;
			assert(state->avg_latency < 1e8f);
			//if(drand48() < .03f) printf("u/b=%f min_l=%.0fus avg_l=%.0fus\n", state->us_per_byte, state->min_latency, state->avg_latency);
			if(lat > 0) lat *= 2.f;
			dt = state->avg_latency-state->min_latency;
			float k = lat/dt;
			state->send_window += (uint64_t)(int64_t)(lat + dt*ipprt*.5f);
			state->growth += k*-.5f + .0625f*ipprt;
			if(state->growth > 0.f) state->growth = 0.f;
			if(state->growth < -8.f) state->growth = -8.f;
		}
		adj_end:
		free(p);
		if(i == 0){
			do{
				i += sizeof(struct _send_packet**);
				if(i == sz){
					state->unsent_i = 0;
					ring_buffer_clear(&state->send_queue);
					return;
				}
				ring_buffer_get(&state->send_queue, i, &spacket, sizeof(spacket), true);
			}while(!spacket && i < state->unsent_i);
			ring_buffer_shift_discard(&state->send_queue, i, false);
			state->unsent_i -= i; sz -= i; i0 -= i;
		}else{
			spacket = 0;
			ring_buffer_set(&state->send_queue, i, &spacket, sizeof(spacket), true);
		}
		//if(DEBUG) check_send(state);
		goto next;
	}
}

// TODO: refactor this function
// Currently, it serves
// _queue_ack(_, lo, hi, 0, true) when i==0 => ack only [lo,hi]
// _queue_ack(_, lo, hi, 0, true) when i>0 => send what's there, don't add [lo,hi]
// _queue_ack(_, lo, hi, t, _) when i==0 => append and conditionally send
// We should separate the queueing and sending logic into 2 functions
static void _queue_ack(struct _hivemind_remote* state, uint64_t lo, uint32_t hi, uint64_t t, bool imm){
	unsigned i = state->ack_coal_i;
	//if(t || !i) assert(validate_ack(state, lo));
	if(t){
		if(!i) add: {
			state->ack_coal_buf[14] = (uint32_t)lo;
			state->ack_coal_tim0 = t;
			state->ack_coal_i = i = 1;
		}else{
			t = ((t<<8)-(state->ack_coal_tim0<<8)) >> 8;
			uint32_t seq = (uint32_t)lo-state->ack_coal_buf[14];
			if(t >= 0x1000000 || seq != (uint32_t)((int32_t)(seq<<24)>>24)){
				_resolve_seq(&lo, &hi, state->ack_coal_buf[14]);
				goto imm;
			}
			seq = (seq&0xFF)|(uint32_t)t<<8;
			if(i == 15) imm = true;
			if(imm) _resolve_seq(&lo, &hi, state->ack_coal_buf[14]);
			state->ack_coal_buf[i-1] = seq;
			state->ack_coal_i = ++i;
		}
	}else if(i) _resolve_seq(&lo, &hi, state->ack_coal_buf[14]);
	else i = 1;
	if(imm) imm: {
		uint32_t chacha[29] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}; // "expand 32-byte k"
		memcpy(chacha+4, state->recv_key, 32);
		chacha[12] = 0xFFFFFFFE; // Should never collide with states used by actual payload
		chacha[13] = (uint32_t)lo; chacha[14] = (uint32_t)(lo>>32); chacha[15] = hi;
		ChaCha20_block(chacha);
		//printf("acking [%u,%llu]+%u\n", hi, lo, i-1);
		uint8_t* const packet = (uint8_t*)(chacha+8);
		uint32_t* const pl = (uint32_t*)(packet+16);
		pl[0] = htole32(lo);
		for(unsigned j = 1; j < i; j++)
			pl[j] = htole32(state->ack_coal_buf[j-1]);
		Poly1305(packet+20, (i<<2)-4, (uint8_t*)chacha, packet);
		bool send_success = x_udp_send(state->handle, (remote_t){state->addr, state->port, 0, 0}, (char*)packet, 16+(i<<2));
		soft_assert(send_success);
		state->ack_coal_i = 0;
		if(!imm) goto add; // forced immediate send from overflow
	}else if(!state->unsent_ack_next){
		struct _hivemind_remote* n = atomic_load_explicit(&_hivemind_meta.unsent_ack, memory_order_acquire);
		retry: state->unsent_ack_next = n;
		if(!atomic_compare_exchange_weak_explicit(&_hivemind_meta.unsent_ack, &n, state, memory_order_acq_rel, memory_order_relaxed)) goto retry;
		x_event_queue_wake(&_hivemind_meta.queue, SEND_TICK);
	}
}

static bool _filter_send_queue(hivemind_server_t* s, struct _hivemind_remote* state, uint32_t pipe0[5], uint32_t pipe1[5], bool first){
	uint64_t lo0 = state->send_seq_lo; uint32_t hi = state->send_seq_hi;
	size_t sz = ring_buffer_size(&state->send_queue);
	uint64_t lo1 = lo0 - sz/sizeof(struct _send_packet*);
	if(lo1>lo0) hi--;
	// ACK ERR, filter out bad pipes and make new kEX
	size_t ir = state->unsent_i, i = ir;
	// Trim off all packets with any amount of acks
	while(ir){
		struct _send_packet** s;
		ring_buffer_get(&state->send_queue, ir -= sizeof(s), &s, sizeof(s), true);
		if(!s) break;
		struct _send_packet* p = *s; assert(p);
		ring_buffer_set(&state->send_queue, ir, &p, sizeof(p), true);
		if(p->first) i = ir;
	}
	// opts 3 => ack err for kEX packet only. If it is a kEX packet, it will be rejected by opts 3 and doesn't need a probe packet. Performing this check splits us neatly into 2 cases, one of which need never worry about kEX packets in the queue.
	if(first ^ (!i && !lo1 && !hi && state->unsent_i)) return false;
	ring_buffer_t old_queue = state->send_queue;
	ring_buffer_clear(&state->send_queue);
	uint32_t chacha_in[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}; // "expand 32-byte k"
	memcpy(chacha_in+4, state->send_key, 32);
	size_t qd = 0;
	if(first){
		// Shift the first message (which must be the kEX)
		struct _send_packet* p;
		ring_buffer_get(&old_queue, i, &p, sizeof(p), true);
		// We flattened the queue so every entry points to the packet and not the prev
		assert(p && p->first);
		unsigned p_payload_len = (unsigned)(p->len_p-1)<<5;
		size_t len = read_len_inc(p->payload+36);
		i += sizeof(p);
		free(p);
		while(len > p_payload_len){
			len -= p_payload_len;
			ring_buffer_get(&old_queue, i, &p, sizeof(p), true);
			p_payload_len = (unsigned)p->len_p<<5;
			i += sizeof(p);
			free(p);
		}
	}else for(size_t j = 0; j < i; j += sizeof(struct _send_packet*)){
		struct _send_packet* p;
		ring_buffer_get(&old_queue, j, &p, sizeof(p), true);
		free(p);
	}
	while(i < sz){
		struct _send_packet* p;
		ring_buffer_get(&old_queue, i, &p, sizeof(p), true);
		assert(p); // By waiting for send_unlocked_ref to reach 0 there shouldn't be any blank spots in the unsent section anymore
		unsigned p_payload_len = (unsigned)p->len_p<<5;
		size_t lseq = lseqof(p);
		if(i < state->unsent_i){
			chacha_in[13] = (uint32_t)lseq;
#if SIZE_MAX == UINT64_MAX
			chacha_in[14] = (uint32_t)(lseq>>32);
			chacha_in[15] = hi + (uint32_t)(lseq < lo1);
#else
			uint64_t hi1 = (uint64_t)hi<<32|(uint64_t)lo1>>32 + (uint32_t)(lseq < (size_t)lo1);
			chacha_in[14] = (uint32_t)(hi1>>32); chacha_in[15] = (uint32_t)hi1;
#endif
			chacha_in[12] = 0;
			ChaCha20_block_xor(chacha_in, p->payload+20, 1);
		}
		if(p->first && !_pipeid_in_range((uint32_t*)(p->payload+20), pipe0, pipe1)){
			// Skip entire message
			size_t len = read_len_inc(p->payload+20);
			i += sizeof(p);
			free(p);
			while(len > p_payload_len){
				len -= p_payload_len;
				ring_buffer_get(&old_queue, i, &p, sizeof(p), true);
				p_payload_len = (unsigned)p->len_p<<5;
				i += sizeof(p);
				free(p);
			}
			continue;
		}
		if(i < state->unsent_i && p_payload_len > 64){
			chacha_in[12] = 1;
			ChaCha20_block_xor(chacha_in, p->payload+84, (p_payload_len>>6)-1);
		}
		if(!qd){
			// First packet, do a new kEX
			struct _send_packet* p2 = _hivemind_alloc(sizeof(struct _send_packet) + 36 + 64);
			_ram_packed_kex(s, (uint32_t*)(p->payload+20), state, (uint32_t*)(p2->payload+16));
			memcpy(p2->payload+56, p->payload+40, 44);
			p2->first = 1; p2->resent = 0;
			p2->len_p = (36 + 64)>>5;
			ring_buffer_push(&state->send_queue, &p2, sizeof(p2), true);
			qd = 1;
			if(p_payload_len > 64){
				// Split into kEX + rest
				memmove(p->payload+20, p->payload+84, p_payload_len -= 64);
				p->len_p = p_payload_len>>5; p->first = 0;
				goto reencode;
			}else{
				// everything is included in that packet we just queued
				free(p);
			}
		}else reencode: {
			p->resent = 0;
			*(uint32_t*)(p->payload+16) = htole32(qd);
			ring_buffer_push(&state->send_queue, &p, sizeof(p), true);
			qd++;
		}
	}
	ring_buffer_destroy(&old_queue);
	state->unsent_i = 0;
	state->send_order_start = 0;
	state->send_order_end = &state->send_order_start;
	state->rtt_gate_hi = 0;
	state->rtt_gate_lo = state->unsent_i < ring_buffer_size(&state->send_queue) ? 6 : 0;
	// If there are packets to send, there were already packets to send, and therefore it's already in the drain write list
	return !qd; // If no messages were actually queued, force kEX next time
}

static void _send_probe_ack_err(hivemind_server_t* s, uint32_t opts, remote_t from){
	uint8_t packet2[80];
	uint32_t* knonce = (uint32_t*)(packet2+20);
	_nalloc_id(s, knonce+8);
	knonce[14] = knonce[8];
	memcpy(knonce+4, s->first_id, 20);
	knonce[13] = knonce[4];
	uint32_t poly_key[8];
	_keyless_sig(s, &from, knonce, poly_key, knonce+5, 8);
	*(uint32_t*)(packet2+16) = knonce[0]; knonce[0] = htole32(opts<<8);
	uint32_t tmp = knonce[4]; knonce[4] = opts;
	Poly1305(packet2+36, 44, (uint8_t*)poly_key, packet2);
	knonce[4] = tmp;
	bool send_success = x_udp_send(s->handle, from, (char*)packet2, 80);
	soft_assert(send_success);
}

static uint8_t* _drain_reads(hivemind_server_t* s, uint8_t* packet, unsigned buflen, bool original){
	for(unsigned read_count = 0;;){
		remote_t from;
		unsigned plen = (unsigned)x_udp_next_read(s->handle, &from, (char*)packet, buflen);
		if((int)plen < 0) break;
		if(plen < 20 || (plen&3)) continue;
		if(++read_count == 256){
			// Only the original reader should request help
			// quadratic increase is enough, exponential increase is dangerous
			hivemind_server_t* expected = 0;
			if(atomic_compare_exchange_strong_explicit(&_hivemind_meta.read_help_requested, &expected, s, memory_order_release, memory_order_relaxed)) x_event_queue_wake(&_hivemind_meta.queue, 0);
			else read_count = 255; // if we fail, we should try again immediately next time
		}
		uint32_t seq = le32toh(*(uint32_t*)(packet+16));
		if(plen < 84){
			// ack
			struct _hivemind_remote* state = _hivemind_state_find(s, from.addr, from.port, false);
			if likely(plen == 20 || packet[20] != 0){
				if(!state) continue;
				_time_lock_acq(&state->send_last_used);
				uint64_t tim = _hivemind_internal_clock();
				shared_lock_release(&s->state_lock);
				_hivemind_ackd(state, packet, plen, tim);
				_time_lock_rel(&state->send_last_used, tim);
				continue;
			}
			unsigned payload_len = plen-40;
			uint32_t* knonce = (uint32_t*)(packet+20);
			uint32_t opts = le32toh(*knonce)>>8;
			knonce[0] = *(uint32_t*)(packet+16);
			uint32_t tag[4], *ptag = (uint32_t*)packet;
			uint32_t poly_key[8];
			_keyless_sig2(s, &from, knonce, poly_key, (uint32_t*)(packet+40), payload_len > 32 ? 8 : payload_len>>2);
			*(uint32_t*)(packet+36) = htole32(opts<<8);
			if(payload_len) Poly1305(packet+36, payload_len+4, (uint8_t*)poly_key, (uint8_t*)tag);
			else memcpy(tag, poly_key, 16);
			if(memcmp16(tag, ptag)){
				if(state) shared_lock_release(&s->state_lock);
				continue; // sig failed
			}
			if(opts&2){
				if(!state) continue;
				if(payload_len != 40) rel: {
					shared_lock_release(&s->state_lock);
					continue;
				}
				// ack err
				_time_lock_acq(&state->send_last_used);
				shared_lock_release(&s->state_lock);
				uint64_t tim = _hivemind_internal_clock();
				if(state->send_unlocked_ref){
					if(state->send_unlocked_ref&0x80000000) goto end;
					state->send_unlocked_ref |= 0x80000000;
					retry:
					_time_lock_rel(&state->send_last_used, tim);
					thread_sleep(1); // Very strong yield
					_time_lock_acq(&state->send_last_used);
					if(state->send_unlocked_ref & 0x7FFFFFFF) goto retry;
					state->send_unlocked_ref = 0;
				}
				uint32_t pipe0[5]; pipe0[0] = *(knonce+13); memcpy(pipe0+1, knonce+5, 16);
				*(knonce+8) = *(knonce+14);
				if(_filter_send_queue(s, state, pipe0, knonce+8, opts&1)) tim = 1;
				end:
				_time_lock_rel(&state->send_last_used, tim);
			}else if(opts&1){
				if(!state) continue;
				// probe ack
				_time_lock_acq(&state->send_last_used);
				shared_lock_release(&s->state_lock);
				state->rtt_gate_lo = state->rtt_gate_hi = 0;
				for(size_t i = 0; i < state->unsent_i; i += sizeof(struct _send_packet*)){
					struct _send_packet** p;
					ring_buffer_get(&state->send_queue, i, &p, sizeof(p), true);
					if(p) (*p)->resent = 0;
				}
				_time_lock_rel(&state->send_last_used, _hivemind_internal_clock());
			}else if(!payload_len){
				// probe, respond with probe ack or probe ack err
				if(!state) err: {
					_send_probe_ack_err(s, 2, from);
					continue;
				}
				uint64_t l = _time_lock_peek(&state->send_last_used);
				shared_lock_release(&s->state_lock);
				if(l == 1) goto err;
				// ack
				uint32_t poly_key[8];
				_keyless_sig(s, &from, knonce, poly_key, 0, 0);
				opts = htole32(1);
				Poly1305((uint8_t*)&opts, 4, (uint8_t*)poly_key, (uint8_t*)ptag);
				*(uint32_t*)(packet+16) = knonce[0]; knonce[0] = htole32(1<<8);
				bool send_success = x_udp_send(s->handle, from, (char*)packet, 40);
				soft_assert(send_success);
			}else if(state) shared_lock_release(&s->state_lock);
			continue;
		}
		uint32_t chacha_in[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}; // "expand 32-byte k"
		unsigned header = plen&63; plen -= header;
		if(header != 20 && header != 36) continue;
		uint64_t kdw;
		uint32_t pipeid[5];
		if unlikely(header == 36){
			// New connection requested
			// We should really reject invalid new connections as soon as possible
			// This is what _ram_packed_kex_verify does
			memcpy(pipeid, packet+36, 20);
			kdw = _ram_packed_kex_verify(s, &from, chacha_in+4, (uint32_t*)(packet+16), pipeid);
			if(!kdw) continue;
		}
		struct _hivemind_remote* state = _hivemind_state_find(s, from.addr, from.port, header == 36);
		if unlikely(!state) continue;
		uint64_t l = _time_lock_acq(&state->recv_last_used);
		uint64_t tim = _hivemind_internal_clock();
		shared_lock_release(&s->state_lock);
		uint64_t lo = 0; uint32_t hi = 0;
		size_t idx;
		if likely(header != 36){
			if(l == 1){
				_time_lock_rel(&state->recv_last_used, l);
				continue;
			}
			memcpy(chacha_in+4, state->recv_key, 32);
			lo = state->recv_seq_lo; hi = state->recv_seq_hi;
			_resolve_seq(&lo, &hi, seq);
			idx = lo - state->recv_seq_lo;
			if(idx > 0xFFFFFFFF) ack_abort: {
				_queue_ack(state, lo, hi, tim, false);
				_time_lock_rel(&state->recv_last_used, tim);
				continue;
			}
			idx *= sizeof(sfat_pointer_t);
			if(idx > 0 && idx < ring_buffer_size(&state->recv_queue)){
				sfat_pointer_t p;
				ring_buffer_get(&state->recv_queue, idx, &p, sizeof(sfat_pointer_t), true);
				if(p) goto ack_abort;
			}
			chacha_in[13] = (uint32_t)lo; chacha_in[14] = (uint32_t)(lo>>32); chacha_in[15] = hi;
		}
		//printf("got %llu\n", lo);
		state->recv_unlocked_ref++;
		_time_lock_rel(&state->recv_last_used, tim);
		uint32_t d[16]; memcpy(d, chacha_in, 64);
		d[12] = 0xFFFFFFFF; ChaCha20_block(d);
		uint8_t* p = packet + header;
		Poly1305(p, plen, (uint8_t*) d, (uint8_t*)(d+8));
		uint32_t *ptag = (uint32_t*)packet;
		if(memcmp16(d+8, ptag)){
			l = _time_lock_acq(&state->recv_last_used);
			state->recv_unlocked_ref--;
			_time_lock_rel(&state->recv_last_used, l);
			continue; // poly failed
		}
		chacha_in[12] = 0;
		ChaCha20_block_xor(chacha_in, p, plen>>6);
		if(header == 36) memcpy(p, pipeid, 20);
		l = _time_lock_acq(&state->recv_last_used);
		state->recv_unlocked_ref--;
		if unlikely(header == 36){
			//printf("%llu\n", kdw);
			if unlikely(kdw == -1ull){
				// Pipe range test failed, send probe ack err
				_send_probe_ack_err(s, 3, from);
				_time_lock_rel(&state->recv_last_used, l);
				continue;
			}else if(kdw <= state->key_derived_when){
				unsigned ackv = state->ack_coal_i;
				state->ack_coal_i = 0;
				_queue_ack(state, 0, 0, 0, true);
				state->ack_coal_i = ackv;
				_time_lock_rel(&state->recv_last_used, l);
				continue;
			}
			state->key_derived_when = kdw;
			state->recv_seq_lo = 0; state->recv_seq_hi = 0;
			_hivemind_remote_cleanup_recv(state);
			state->ack_coal_i = 0;
			memcpy(state->recv_key, chacha_in+4, 32);
			if(!DEBUG) _queue_ack(state, 0, 0, 0, true);
		}else if(!DEBUG) _queue_ack(state, lo, hi, tim, false);
		
		idx = lo - state->recv_seq_lo;
		if(idx > 0xFFFFFFFF){
			_time_lock_rel(&state->recv_last_used, l);
			continue;
		}
		idx *= sizeof(sfat_pointer_t);
		size_t contents = ring_buffer_size(&state->recv_queue);
		if(!idx){
			// At tail. We dequeue as many packets as we can and compile them into the
			// current "working" packet and fire message events when it is full
			uint8_t* cur_head = 0;
			if(contents){
				sfat_pointer_t head_;
				ring_buffer_get(&state->recv_queue, 0, &head_, sizeof(sfat_pointer_t), true);
				cur_head = sfat_get(head_);
				assert(!sfat_size(head_));
			}
			do{
				if(!state->cur_packet){ // create new
					assert(!cur_head);
					uint64_t len;
					uint8_t* p2 = p;
					assert(plen >= 26); // plen should be at least 64 in all cases
					len = le16toh(*(uint16_t*)(p+20));
					if(len&1){
						len = (len>>1 | (uint64_t)le16toh(*(uint16_t*)(p+22))<<15 | (uint64_t)le16toh(*(uint16_t*)(p+24))<<31) + 1;
						p2 += 26; plen -= 26;
					}else len >>= 1, p2 += 22, plen -= 22;
					if(plen >= len){
						uint32_t* id = (uint32_t*)p;
						for(unsigned i = 0; i < 5; i++) id[i] = le32toh(id[i]);
						tls.packet_on_heap = p == packet+header ? len : SIZE_MAX-1;
						bool success = _fire_pipe(s, id, p2, len);
						assert(success);
						if(tls.packet_on_heap == SIZE_MAX-1) free(p - ((uintptr_t)p&7 ? 20 : 0));
					}else{
#if SIZE_MAX < 0x7FFFFFFFFFFF-20
						if unlikely(len > SIZE_MAX){
							fputs("hivemind: _drain_reads(): Message size exhausts user address space", stderr);
							abort();
						}
#endif
						uint8_t* new_packet = state->cur_packet = (uint8_t*) _hivemind_alloc((size_t)len+20);
						uint32_t* id = (uint32_t*) new_packet;
						for(unsigned i = 0; i < 5; i++) id[i] = le32toh(((uint32_t*)p)[i]);
						memcpy(new_packet+20, p2, plen);
						cur_head = state->cur_packet + 20 + plen;
						state->cur_packet_left = len - plen;
						if(p != packet+header) free(p - ((uintptr_t)p&7 ? 20 : 0));
					}
				}else{ // append
					assert(cur_head);
					if(state->cur_packet_left <= plen) plen = (unsigned)(state->cur_packet_left);
					memcpy(cur_head, p, plen);
					cur_head += plen;
					if(state->cur_packet_left == plen){
						size_t sz = (size_t)(cur_head - state->cur_packet) - 20;
						uint8_t* p2 = state->cur_packet;
						tls.packet_on_heap = SIZE_MAX-1;
						bool success = _fire_pipe(s, (uint32_t*)p2, p2+20, sz);
						assert(success);
						if(tls.packet_on_heap == SIZE_MAX-1) free(p2);
						state->cur_packet = 0; cur_head = 0;
					}else state->cur_packet_left -= plen;
					if(p != packet+header) free(p - ((uintptr_t)p&7 ? 20 : 0));
				}
				idx += sizeof(sfat_pointer_t);
				if(idx < contents){
					sfat_pointer_t p0;
					ring_buffer_get(&state->recv_queue, idx, &p0, sizeof(sfat_pointer_t), true);
					p = sfat_get(p0); plen = sfat_size(p0);
				}else p = 0;
			}while(p);
			uint64_t lo1 = state->recv_seq_lo;
			state->recv_seq_lo += idx/sizeof(sfat_pointer_t);
			if(state->recv_seq_lo < lo1) state->recv_seq_hi++;
			sfat_pointer_t head_ = sfat_pack(cur_head, 0);
			if(idx >= contents){
				ring_buffer_clear(&state->recv_queue);
				if(cur_head) ring_buffer_push(&state->recv_queue, &head_, sizeof(head_), true);
			}else if(idx < contents){
				ring_buffer_shift_discard(&state->recv_queue, idx, false);
				if(DEBUG){
					sfat_pointer_t p2;
					ring_buffer_get(&state->recv_queue, 0, &p2, sizeof(p2), true);
					assert(!p2);
				}
				ring_buffer_set(&state->recv_queue, 0, &head_, sizeof(head_), true);
			}
		}else{
			// Queue packet into the ring buffer, to be later consumed by the dequeue steps when holes are filled
			assert(header == 20); // This should be impossible as the first (key exchange) packet
			uint8_t* r;
			// Must be at least 62.5% used to be considered "worth" it
			if(plen >= (buflen>>1)+(buflen>>3)){
				r = packet+header;
				packet = (uint8_t*) _hivemind_alloc(buflen);
			}else{
				r = (uint8_t*) _hivemind_alloc(plen);
				memcpy(r, p, plen);
			}
			size_t idx2 = idx + sizeof(sfat_pointer_t);
			if(contents < idx2)
				ring_buffer_push_memset(&state->recv_queue, 0, idx2-contents, false);
			sfat_pointer_t m = sfat_pack(r, plen);
			ring_buffer_set(&state->recv_queue, idx, &m, sizeof(m), true);
		}
		if(DEBUG){
			if unlikely(header == 36) _queue_ack(state, 0, 0, 0, true);
			else _queue_ack(state, lo, hi, tim, false);
		}
		_time_lock_rel(&state->recv_last_used, l);
	}
	return packet;
}

static void* _hivemind_listen(void* _){
#ifdef _POSIX_THREADS
	sigset_t set; sigfillset(&set);
	pthread_sigmask(SIG_BLOCK, &set, 0);
#endif

	struct _hivemind_thread self = {.hazard = 0};
	self.prevp = &_hivemind_meta.threads;
	lock_acquire(&_hivemind_meta.threads_lock, 1);
	struct _hivemind_thread* next = atomic_load_explicit(&_hivemind_meta.threads, memory_order_relaxed);
	atomic_init(&self.next, next);
	if(next) next->prevp = &self.next;
	atomic_store_explicit(&_hivemind_meta.threads, &self, memory_order_release);
	lock_release(&_hivemind_meta.threads_lock, 1);

	uint8_t* packet = 0; unsigned packetsz = 0;
	for(;;){
		x_event_t ev = x_event_queue_wait(&_hivemind_meta.queue, -1ull);
		tsan_fence(memory_order_acquire);
		if(ev.type & (X_EVENT_READABLE/*|X_EVENT_WRITABLE*/))
			atomic_store_explicit(&self.hazard, ev.data.ptr, memory_order_relaxed);
		x_event_queue_unlock(&_hivemind_meta.queue);
		if(ev.type == X_EVENT_WAKE){
			hivemind_server_t* s_s = atomic_load_explicit(&_hivemind_meta.servers, memory_order_relaxed);
			if unlikely(!s_s){
				x_event_queue_wake(&_hivemind_meta.queue, 0);
				break;
			}
			hivemind_server_t* help = atomic_load_explicit(&_hivemind_meta.read_help_requested, memory_order_relaxed);
			if(help){
				retry:
				atomic_store_explicit(&self.hazard, help, memory_order_relaxed);
				//thread_memory_barrier(mb_co_acquire); // order protected by the `acq_rel` xchg
				if(help == atomic_exchange_explicit(&_hivemind_meta.read_help_requested, 0, memory_order_acq_rel)){
					x_event_queue_wake(&_hivemind_meta.queue, 0); // someone else deal with any wakes
					ev.data.ptr = help;
					goto recv_packet;
				} // if changed, another wakeup will handle it
			}
			uint64_t wake = GC_FREQ;
			// early test
			uint64_t tim = _hivemind_internal_clock();
			if(atomic_load_explicit(&_hivemind_meta.unsent_ack, memory_order_relaxed) > (struct _hivemind_remote*)1){
				struct _hivemind_remote* state = atomic_exchange_explicit(&_hivemind_meta.unsent_ack, 0, memory_order_acquire), *head = state, **prev = &head;
				new_unsent_acks:
				while(state > (struct _hivemind_remote*)1){
					uint64_t l = _time_lock_acq(&state->recv_last_used);
					struct _hivemind_remote* n = state->unsent_ack_next;
					if(!state->ack_coal_i) goto rem;
					if((((tim<<8) - (state->ack_coal_tim0<<8)) >> 8) >= SEND_TICK){
						_queue_ack(state, state->recv_seq_lo, state->recv_seq_hi, 0, true);
						rem:
						*prev = n;
						state->unsent_ack_next = 0;
						if unlikely(state->handle == X_SOCKET_INVALID && !state->undrained_next){
							free(state);
							goto next_a;
						}
					}else prev = &state->unsent_ack_next;
					_time_lock_rel(&state->recv_last_used, l);
					next_a: state = n;
				}
				state = 0;
				if(!atomic_compare_exchange_strong_explicit(&_hivemind_meta.unsent_ack, &state, head, memory_order_relaxed, memory_order_acquire)){
					*prev = state;
					goto new_unsent_acks;
				}
				if(head > (struct _hivemind_remote*)1) wake = SEND_TICK;
			}
			// early test
			if(atomic_load_explicit(&_hivemind_meta.undrained, memory_order_relaxed) > (struct _hivemind_remote*)1){
				struct _hivemind_remote* state = atomic_exchange_explicit(&_hivemind_meta.undrained, 0, memory_order_acquire), *head = state, **prev = &head;
				new_undraineds:
				while(state > (struct _hivemind_remote*)1){
					uint64_t l = _time_lock_acq(&state->send_last_used);
					uint64_t tim = _hivemind_internal_clock();
					struct _hivemind_remote* n = state->undrained_next;
					if(!ring_buffer_size(&state->send_queue)){
						*prev = n;
						state->undrained_next = 0;
						if unlikely(state->handle == X_SOCKET_INVALID && !state->unsent_ack_next){
							free(state);
							goto next_u;
						}
					}else{
						_drain_writes(state, tim);
						prev = &state->undrained_next;
					}
					_time_lock_rel(&state->send_last_used, tim);
					next_u: state = n;
				}
				state = 0;
				if(!atomic_compare_exchange_strong_explicit(&_hivemind_meta.undrained, &state, head, memory_order_relaxed, memory_order_acquire)){
					*prev = state;
					goto new_undraineds;
				}
				if(head > (struct _hivemind_remote*)1) wake = SEND_TICK;
			}
			uint64_t last_gc = atomic_load_explicit(&_hivemind_meta.last_gc, memory_order_relaxed);
			if unlikely(s_s && last_gc != -1ull && tim - last_gc > GC_FREQ && atomic_compare_exchange_strong_explicit(&_hivemind_meta.last_gc, &last_gc, -1ull, memory_order_acquire, memory_order_relaxed)){
				for(;;){
					atomic_store_explicit(&self.hazard, s_s, memory_order_relaxed);
					thread_memory_barrier(mb_co_acquire);
					hivemind_server_t* s2 = atomic_load_explicit(&_hivemind_meta.servers, memory_order_acquire);
					if(s2 == s_s) break;
				}
				while(s_s){
					_remove_unused(s_s, tim);
					atomic_store_explicit(&self.hazard, (void*)-1ull, memory_order_relaxed);
					thread_memory_barrier(mb_co_acquire);
					s_s = atomic_load_explicit(&s_s->next, memory_order_acquire);
					atomic_store_explicit(&self.hazard, s_s, memory_order_release);
					thread_memory_barrier(mb_co_acquire);
				}
				atomic_store_explicit(&_hivemind_meta.last_gc, _hivemind_internal_clock(), memory_order_release);
			}
			x_event_queue_wake(&_hivemind_meta.queue, wake);
			continue;
		}
		if(ev.type & X_EVENT_READABLE) recv_packet: {
			hivemind_server_t* s = (hivemind_server_t*) ev.data.ptr;
			atomic_thread_fence(memory_order_acquire);
			uint16_t mtu = le16toh(s->mtu_le);
			if(packetsz < mtu){
				free(packet);
				packet = (uint8_t*) _hivemind_alloc(packetsz = mtu);
			}
			packet = _drain_reads(s, packet, packetsz, ev.type == X_EVENT_READABLE);
			atomic_store_explicit(&self.hazard, 0, memory_order_release);
		}
		/*if(ev.type & X_EVENT_WRITABLE){
			hivemind_server_t* s = (hivemind_server_t*) ev.data.ptr;
			atomic_thread_fence(memory_order_acquire);
			// Server open

			atomic_store_explicit(&self.hazard, 0, memory_order_release);
		}*/
		if(ev.type & X_EVENT_CLOSE){
			hivemind_server_t* s = (hivemind_server_t*) ev.data.ptr;
			hivemind_server_t* expected = s;
			struct _open_close_data* oc = s->oc;
			if(!oc) continue;
			atomic_compare_exchange_strong_explicit(&_hivemind_meta.read_help_requested, &expected, 0, memory_order_relaxed, memory_order_relaxed);
			lock_acquire(&_hivemind_meta.threads_lock, 1);
			hivemind_server_t* next = atomic_load_explicit(&s->next, memory_order_relaxed);
			atomic_store_explicit(s->prevp, next, memory_order_relaxed);
			if(next) next->prevp = s->prevp;
			else if(s->prevp == &_hivemind_meta.servers)
				x_event_queue_wake(&_hivemind_meta.queue, 0);
			lock_release(&_hivemind_meta.threads_lock, 1);
			_hazard_wait(s);
			exclusive_lock_wait(&s->state_lock);
			// Server should be unreachable after this

			// Fearless freeing!
			_hivemind_finish(s, oc->finish_cb, oc->filename[0] ? oc->filename : 0);
			void (*on_close)(void*) = oc->cb;
			
			free(oc);
			
			// Safe to teardown
			x_socket_free(s->handle);
			s->handle = X_SOCKET_INVALID;
			if(on_close) on_close(s->udata);
		}
	}
	free(packet);
	lock_acquire(&_hivemind_meta.threads_lock, 1);
	next = atomic_load_explicit(&self.next, memory_order_relaxed);
	if(next) next->prevp = self.prevp;
	atomic_store_explicit(self.prevp, next, memory_order_release);
	lock_release(&_hivemind_meta.threads_lock, 1);
	return 0;
}