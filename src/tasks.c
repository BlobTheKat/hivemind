#include "plumbing.c"
#ifndef _WIN32
	#include <signal.h>
#endif

// THREAD STACK LINKED LIST!!!
struct _hv_thread{
	atomic(struct _hv_thread*) next, *prevp;
	// Hazard pointer for GC and UDP reads
	atomic(void*) hazard;
};
struct{
	x_event_queue_t queue;
	lock_t threads_lock;
	uint32_t threads_max, threads_cur;
	atomic(struct _hv_remote*) undrained;
	atomic(struct _hv_remote*) unsent_ack;
	atomic(hivemind_server_t*) read_help_requested;
	atomic(uint64_t) last_gc;
	atomic(hivemind_server_t*) servers;
	atomic(struct _hv_thread*) threads;
} _hv_meta = {
	.threads_lock = 1,
	.undrained = (struct _hv_remote*)1,
	.unsent_ack = (struct _hv_remote*)1
};
static_assert(alignof(thread_t) <= alignof(max_align_t));
// Hazard slots in this implementation follow a thread-to-thread linked list (it's all allocated in the stack) protected by threads_lock

// Acquire semantics
static inline void _hv_hazard_wait(void* target){
	struct _hv_thread* t = atomic_load_explicit(&_hv_meta.threads, memory_order_acquire);
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

static void _hv_remove_unused(hivemind_server_t* s, uint64_t t){
	array_buffer_t candidates = {0};
	uint64_t c = s->state_lifetime;
	shared_lock_acquire(&s->state_lock);
	size_t buckets = (1<<s->buckets_exp&-2ull)>>1;
	struct _hv_remote** l = s->remote_buckets;
	if(buckets < 2) l = (struct _hv_remote**) &s->remote_buckets;
	for(size_t b = 0; b < buckets; b++){
		struct _hv_remote* state = s->remote_buckets[b];
		while(state){
			if(state->bypass_type&2){
				struct _hv_remote_vq* state_vq = (struct _hv_remote_vq*) state;
				uint64_t last_used = atomic_load_explicit(&state_vq->vq_last_used, memory_order_relaxed);
				if(last_used-t > c) array_buffer_push(&candidates, &state, sizeof(state));
			}else{
				uint64_t r = atomic_load_explicit(&state->recv_last_used, memory_order_relaxed);
				uint64_t s = atomic_load_explicit(&state->send_last_used, memory_order_relaxed);
				if(r && s && (r-t+1)>>1 > c && s-t > c){
					array_buffer_push(&candidates, &state, sizeof(state));
				}
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
	struct _hv_remote* state, **prevp;
	while(array_iterator_next(&it, &state, sizeof(state))){
		if(state->bypass_type&2){
			struct _hv_remote_vq* state_vq = (struct _hv_remote_vq*) state;
			uint32_t ref = atomic_load_explicit(&state_vq->ref, memory_order_acquire);
			if(ref) continue;
			uint64_t last_used = atomic_load_explicit(&state_vq->vq_last_used, memory_order_relaxed);
			if(last_used-t <= c) continue;
			vqueue_close(&state_vq->q);
			prevp = state_vq->prevp;
		}else{
			uint64_t r = _hv_time_lock_acq(&state->recv_last_used);
			uint64_t s = _hv_time_lock_acq(&state->send_last_used);
			t = _hv_internal_clock();
			if(state->send_unlocked_ref || state->recv_unlocked_ref || state->undrained_next || state->unsent_ack_next || (r-t+1)>>1 <= c || s-t <= c){
				_hv_time_lock_rel(&state->recv_last_used, r);
				_hv_time_lock_rel(&state->send_last_used, s);
				continue;
			}
			// FREE!!!
			_hv_remote_cleanup_recv(state, state->bypass_type);
			_hv_remote_cleanup_send(state);
			prevp = state->prevp;
		}
		*prevp = state->next;
		struct _hv_remote* next = state->next;
		if(next){
			if(next->bypass_type&2) ((struct _hv_remote_vq*)next)->prevp = prevp;
			else next->prevp = prevp;
		}
		free(state);
	}
	array_buffer_destroy(&candidates);
	exclusive_lock_release(&s->state_lock);
}

static void _hv_send_packet(struct _hv_remote* state, struct _hv_send_packet* packet, uint64_t now, bool bypass){
	//printf("send %zu i=%zu\n", _hv_lseqof(packet), i);
	unsigned len = packet->len4<<2;
	if(bypass && packet->first) len -= packet->kex ? 2 : 1;
	bool send_success = x_udp_send(_hv_state_handle(state), (remote_t){state->addr, state->port, 0, 0}, (char*)packet->payload4, len);
	soft_assert(send_success);
	packet->next = 0; packet->time_lo = now;
}

static uint64_t _hv_drain_writes(struct _hv_remote* state, uint64_t now, bool bypass){
	if unlikely((state->rtt_gate_lo&5)==4){
		// network partition
		uint32_t rtt_gate = (uint32_t)state->rtt_gate_lo|(uint32_t)state->rtt_gate_hi<<16;
		if(rtt_gate < 256){
			// Timer expired, send a probe packet
			uint8_t packet[40];
			remote_t to = {.addr = state->addr, .port = state->port};
			if(bypass) _hv_crcinitless_packet_finish(state->server, &to, packet, 0, 0);
			else _hv_keyless_packet_finish(state->server, &to, packet, 0, 0);
			unsigned gen = rtt_gate>>3&31;
			if(gen<24) gen++;
			rtt_gate = 4 | gen<<3 | ((1u<<(gen>>1))-1)<<8;
		}else rtt_gate -= 256;
		state->rtt_gate_lo = rtt_gate; state->rtt_gate_hi = rtt_gate>>16;
		return now;
	}
	float left = now-state->send_window;
	if(left > _HV_SEND_BURST){
		left = _HV_SEND_BURST;
		state->send_window = now-_HV_SEND_BURST;
	}
	if(left <= 0) return now;
	size_t sendable_now = /*floor*/ (size_t)(left / state->us_per_byte), sent = 0;
	if(!sendable_now) return now;

	// find unacked
	struct _hv_send_packet *packet = state->send_order_start, *packet0 = packet, *fpacket;
	uint64_t cutoff = (uint64_t)(state->avg_latency*2.);
	if(cutoff < _HV_SEND_TICK*2) cutoff = _HV_SEND_TICK*2;
	cutoff = (now - cutoff) << 20;
	struct _hv_send_packet** replace = 0;
	if(packet) for(;;){
		if((int64_t)((packet->time_lo<<20) - cutoff) >= 0){
			if(packet == packet0) packet0 = 0;
			state->send_order_start = packet;
			break;
		}
		if(packet->resent++ == 15){
			// 16 failed attempts, network partition? remote restarted? we don't know. Go into probe mode
			state->rtt_gate_hi = 0; state->rtt_gate_lo = 4;
			return now;
		}
		sent += (packet->len4<<2)+48;
		size_t i = (_hv_lseqof(packet, bypass) + state->packet_offset-(uint32_t)state->send_seq_lo) * sizeof(struct _hv_send_packet**);
		ring_buffer_set(&state->send_queue, i, &replace, sizeof(replace), true);
		packet = packet->next;
		if(sent >= sendable_now) goto stop;
		if(!packet){
			state->send_order_end = &state->send_order_start;
			stop:
			state->send_order_start = packet;
			break;
		}
	}
	if(packet){
		size_t i = (_hv_lseqof(packet, bypass) + state->packet_offset-(uint32_t)state->send_seq_lo) * sizeof(struct _hv_send_packet**);
		replace = &state->send_order_start;
		ring_buffer_set(&state->send_queue, i, &replace, sizeof(replace), true);
	}
	state->send_unlocked_ref++;
	fpacket = packet;
	if((packet = packet0)){
		state->send_window += (uint64_t)((double)sent*(double)state->us_per_byte);
		sendable_now = sent > sendable_now ? 0 : sendable_now-sent; sent = 0;
		_hv_time_lock_rel(&state->send_last_used, now);

		// This outside of critical section
		for(;;){
			// Resent lost packet
			struct _hv_send_packet* next = packet->next;
			_hv_send_packet(state, packet, now, bypass);
			if(next == fpacket){ packet->next = 0; break; }
			packet = next;
		}

		now = _hv_time_lock_acq(&state->send_last_used);
		packet = packet0;
		if(!state->prevp){ // server shutdown
			while(packet){
				struct _hv_send_packet* next = packet->next;
				free(packet); packet = packet->next;
			}
			goto end;
		}
		float left = now-state->send_window;
		if(left > _HV_SEND_BURST){
			left = _HV_SEND_BURST;
			state->send_window = now-_HV_SEND_BURST;
		}
		sendable_now = /*floor*/ left >= 0 ? (size_t)(left / state->us_per_byte) : 0;

		*state->send_order_end = packet0;
		replace = state->send_order_end;
		state->send_order_end = &packet->next;
		while(packet){
			size_t i = (_hv_lseqof(packet, bypass) + state->packet_offset-(uint32_t)state->send_seq_lo) * sizeof(struct _hv_send_packet**);
			ring_buffer_set(&state->send_queue, i, &replace, sizeof(replace), true);
			replace = &packet->next;
			packet = *replace;
		}
	}

	// drain unsent
	again: {}
	size_t sz = array_buffer_size(&state->pipes_with_unsent);
	if(!sz){
		// Don't measure throughput for a gap where we're not even trying
		state->rtt_gate_lo = 0;
		state->rtt_gate_hi = 0;
		goto end;
	}
	if(sendable_now){
		uint32_t chacha_in[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}; // "expand 32-byte k"
		if(!bypass) memcpy(chacha_in+4, state->send_key, 32);
		else chacha_in[4] = state->send_crcinit, chacha_in[5] = state->send_crcinit>>32;
		char* unsent_data = array_buffer_data(&state->pipes_with_unsent);
		size_t iter_i = state->unsent_iter_i;
		again2:
		if(!iter_i) goto find;
		struct _hv_send_pipe* pipe_state = (struct _hv_send_pipe*)(unsent_data+iter_i) - 1;
		struct _hv_send_packet *packet = pipe_state->start;
		if((uintptr_t)packet & 1)
			goto find;
		size_t i = (_hv_lseqof(packet, bypass) + state->packet_offset-(uint32_t)state->send_seq_lo);
		if(i > 0x7FFFFF00){
			find: {}
			size_t best = (size_t)(-1), best_i;
			for(size_t i = 0; i < sz; i += sizeof(struct _hv_send_pipe)){
				struct _hv_send_pipe* ps = (struct _hv_send_pipe*)(unsent_data+i);
				if((uintptr_t)ps->start & 1) continue;
				if(ps->start) continue;
				if(ps->queued < best) best = ps->queued, best_i = i;
			}
			iter_i = state->unsent_iter_i = best_i + sizeof(struct _hv_send_pipe);
			goto again2;
		}
		i *= sizeof(struct _hv_send_packet**);
		if(!(pipe_state->start = packet->next)){
			// remove
			struct _hv_send_pipe* last = (struct _hv_send_pipe*)(unsent_data + sz);
			unsigned cur_rank = hash_table_rank(&state->pipes_with_unsent_b);
			bool rehash = sz <= ((sizeof(struct _hv_send_pipe)>>1) << cur_rank);
			void* true_next = pipe_state->next;
			if(pipe_state != last){
				// remove
				if(!rehash){
					uint64_t hash2 = _hv_mix64((uint64_t)last->id[1]<<32|last->id[4])^_hv_mix64((uint64_t)last->id[2]<<32|last->id[3]);
					size_t p = (size_t)hash_table_find(&state->pipes_with_unsent_b, hash2);
					if(p == sz){
						hash_table_put(&state->pipes_with_unsent_b, hash2, last->next);
					}else while(p){
						struct _hv_send_pipe* p2 = ((struct _hv_send_pipe*)(unsent_data + p)-1);
						p = (size_t)p2->next;
						if(p == sz){
							p2->next = last->next;
							break;
						}
					}
				}
				*pipe_state = *last;
			}
			array_buffer_pop_discard(&state->pipes_with_unsent, sizeof(struct _hv_send_pipe));
			sz -= sizeof(struct _hv_send_pipe);
			if(!rehash){
				uint64_t hash = _hv_mix64((uint64_t)last->id[1]<<32|last->id[4])^_hv_mix64((uint64_t)last->id[2]<<32|last->id[3]);
				size_t p = (size_t)hash_table_find(&state->pipes_with_unsent_b, hash);
				if(p == iter_i){
					hash_table_put(&state->pipes_with_unsent_b, hash, true_next);
				}else while(p){
					struct _hv_send_pipe* p2 = ((struct _hv_send_pipe*)(unsent_data + p)-1);
					p = (size_t)p2->next;
					if(p == iter_i){
						p2->next = true_next;
						break;
					}
				}
			}else{
				hash_table_set_rank(&state->pipes_with_unsent_b, --cur_rank);
				for(unsigned i = 0; i < sz; i += sizeof(struct _hv_send_pipe)){
					struct _hv_send_pipe* ps = (struct _hv_send_pipe*)(unsent_data+i);
					uint64_t hash2 = _hv_mix64((uint64_t)ps->id[1]<<32|ps->id[4])^_hv_mix64((uint64_t)ps->id[2]<<32|ps->id[3]);
					ps->next = hash_table_find(&state->pipes_with_unsent_b, hash2);
					hash_table_put(&state->pipes_with_unsent_b, hash2, (void*)(i + sizeof(struct _hv_send_pipe)));
				}
			}
			state->unsent_iter_i = 0;
		}else if((uintptr_t)pipe_state->start & 1){
			struct _hv_send_packet_placeholder* p2 = (struct _hv_send_packet_placeholder*)((uintptr_t)pipe_state->start-1);
			p2->prevp = &pipe_state->start;
		}
		size_t sending = (packet->len4<<2)+48;
		sendable_now = sending < sendable_now ? sendable_now-sending : 0;
		state->send_window += (uint64_t)(sending*state->us_per_byte);
		_hv_time_lock_rel(&state->send_last_used, now);

		// This outside of critical section
		if(bypass){
			uint64_t crcinit = /*state->send_crcinit*/ chacha_in[4] | (uint64_t)chacha_in[5]<<32, crc;
			if(packet->kex){
				crc = crc64(crcinit, (uint8_t*)packet->payload4, (packet->len4<<2)+2);
				packet->payload4[2] = htole32(crcinit); packet->payload4[3] = htole32(crcinit>>32);
			}else{
				crc = crc64(crcinit, (uint8_t*)packet->payload4, (packet->len4<<2)+(packet->first?3:0));
			}
			packet->payload4[0] = htole32(crc); packet->payload4[1] = htole32(crc>>32);
		}else _hv_encrypt_packet(chacha_in, packet);
		_hv_send_packet(state, packet, now, bypass);

		now = _hv_time_lock_acq(&state->send_last_used);
		if(!state->prevp){ // server shutdown
			free(packet);
			goto end;
		}
		size_t i2 = (_hv_lseqof(packet, bypass) + state->packet_offset-(uint32_t)state->send_seq_lo) * sizeof(struct _hv_send_packet**);
		if(i2 >= ring_buffer_size(&state->send_queue)){
			ring_buffer_push_memset(&state->send_queue, 0, i2 + sizeof(struct _hv_send_packet**) - ring_buffer_size(&state->send_queue), false);
		}
		ring_buffer_set(&state->send_queue, i2, &state->send_order_end, sizeof(struct _hv_send_packet**), true);
		*state->send_order_end = packet;
		state->send_order_end = &packet->next;
		if(!state->send_order_start) state->send_order_start = packet;
		goto again;
	}
	end:
	state->send_unlocked_ref--;
	return now;
}

static inline void _hv_update_throughput(struct _hv_remote* state, struct _hv_send_packet* p, float ithr, float a){
	ithr /= (1 + fast_exp2f(state->growth)) * ((p->len4<<2)+48);
	state->us_per_byte += (ithr-state->us_per_byte)*a;
	assert(state->us_per_byte > 0.f);
}

static void _hv_ackd(struct _hv_remote* state, uint8_t* packet, unsigned plen, uint64_t t0, uint64_t lo0, uint64_t lo2, uint32_t hi, uint64_t i0, bool bypass){
	size_t sz = ring_buffer_size(&state->send_queue);
	uint8_t* packet_end = packet+plen;
	packet += 20;
	if(plen > 20) t0 -= le32toh(*(uint32_t*)(packet_end-4))>>8;
	uint32_t x = 0;
	//if(DEBUG) check_send(state);

	for(;;){
		int8_t delta = (int8_t)(uint8_t)x;
		//printf(packet == packet_end ? "+%d\n" : "+%d", delta);
		size_t i = i0 + (size_t)(ssize_t)delta * sizeof(struct _hv_send_packet**);
		uint64_t t = t0+(x>>8), lo = lo0+(uint64_t)(int64_t)delta;
		if(i >= sz) next: {
			if(packet < packet_end){
				x = le32toh(*(uint32_t*)packet);
				packet += 4;
				continue;
			}else break;
		}
		struct _hv_send_packet** spacket;
		ring_buffer_get(&state->send_queue, i, &spacket, sizeof(spacket), true);
		if(!spacket) goto next;

		struct _hv_send_packet* p = *spacket, *next = p->next;
		if(!(*spacket = next)){
			state->send_order_end = spacket;
		}else{
			size_t i2 = (_hv_lseqof(next, bypass) + state->packet_offset-(uint32_t)state->send_seq_lo) * sizeof(struct _hv_send_packet**);
			ring_buffer_set(&state->send_queue, i2, &spacket, sizeof(spacket), true);
		}
		if(state->send_order_start == p) state->send_order_start = next;
		assert((uint32_t)lo == _hv_lseqof(p, bypass));

		if(!p->resent){
			// ADJUSTMENTS HERE
			float i_minlat = 1.f / state->min_latency;
			if(i_minlat > 1.f/_HV_SEND_TICK) i_minlat = 1.f/_HV_SEND_TICK;
			float ipprt = state->us_per_byte * ((p->len4<<2)+48) * i_minlat;
			if(ipprt > 1.f) ipprt = 1.f;
			float lat = (int64_t)((t - p->time_lo)<<20)>>20;
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
					_hv_update_throughput(state, p, ithr, ipprt*.25f);
					state->avg_latency += (lat - state->avg_latency)*ipprt;
					if unlikely((rtt_gate&5)==4){
						// Partition restored
						state->rtt_gate_hi = 0;
						state->rtt_gate_lo = array_buffer_size(&state->pipes_with_unsent) ? 8 : 0;
					}
					goto adj_end;
				}
			}
			_hv_update_throughput(state, p, ithr, ipprt*.25f);
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
				i += sizeof(struct _hv_send_packet**);
				state->packet_offset--;
				ring_buffer_get(&state->send_queue, i, &spacket, sizeof(spacket), true);
			}while(!spacket && i < sz);
			ring_buffer_shift_discard(&state->send_queue, i, false);
			sz -= i; i0 -= i;
		}else{
			spacket = 0;
			ring_buffer_set(&state->send_queue, i, &spacket, sizeof(spacket), true);
		}
		//if(DEBUG) check_send(state);
		goto next;
	}
}

// Maybe todo: refactor this function
// Currently, it serves
// _hv_queue_ack(_, lo, hi, 0, true) when i==0 => ack only [lo,hi]
// _hv_queue_ack(_, lo, hi, 0, true) when i>0 => send what's there, don't add [lo,hi]
// _hv_queue_ack(_, lo, hi, t, _) when i==0 => append and conditionally send
// We should separate the queueing and sending logic into 2 functions
static void _hv_queue_ack(struct _hv_remote* state, uint64_t lo, uint32_t hi, uint64_t t, bool imm, bool bypass){
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
				_hv_resolve_seq(&lo, &hi, state->ack_coal_buf[14]);
				goto imm;
			}
			seq = (seq&0xFF)|(uint32_t)t<<8;
			if(i == 15) imm = true;
			if(imm) _hv_resolve_seq(&lo, &hi, state->ack_coal_buf[14]);
			state->ack_coal_buf[i-1] = seq;
			state->ack_coal_i = ++i;
		}
	}else if(i) _hv_resolve_seq(&lo, &hi, state->ack_coal_buf[14]);
	else i = 1;
	if(imm) imm: {
		if(bypass){
			uint8_t packet[72];
			*(uint32_t*)packet = htole32(hi); *(uint32_t*)(packet+4) = htole32(lo>>32);
			//printf("acking [%u,%llu]+%u\n", hi, lo, i-1);
			uint32_t* pl = (uint32_t*)(packet+8);
			pl[0] = htole32(lo);
			if(i > 1){
				for(unsigned j = 1; j < i; j++)
					pl[j] = htole32(state->ack_coal_buf[j-1]);
				if(i&1) pl[i++] = 0;
			}
			uint64_t crc = crc64(state->recv_crcinit, packet, 8+(i<<2));
			*(uint32_t*)packet = htole32(crc); *(uint32_t*)(packet+4) = htole32(crc>>32);
			bool send_success = x_udp_send(_hv_state_handle(state), (remote_t){state->addr, state->port, 0, 0}, (char*)packet, 8+(i<<2));
			soft_assert(send_success);
		}else{
			uint32_t chacha[30] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}; // "expand 32-byte k"
			memcpy(chacha+4, state->recv_key, 32);
			chacha[12] = 0xFFFFFFFE; // Should never collide with states used by actual payload
			chacha[13] = (uint32_t)lo; chacha[14] = (uint32_t)(lo>>32); chacha[15] = hi;
			ChaCha20_block(chacha);
			//printf("acking [%u,%llu]+%u\n", hi, lo, i-1);
			uint8_t* packet = (uint8_t*)(chacha+8); // 84 bytes
			uint32_t* pl = (uint32_t*)(packet+16);
			pl[0] = htole32(lo);
			for(unsigned j = 1; j < i; j++)
				pl[j] = htole32(state->ack_coal_buf[j-1]);
			Poly1305(packet+20, (i<<2)-4, (uint8_t*)chacha, packet);
			bool send_success = x_udp_send(_hv_state_handle(state), (remote_t){state->addr, state->port, 0, 0}, (char*)packet, 16+(i<<2)+bypass);
			soft_assert(send_success);
		}
		state->ack_coal_i = 0;
		if(!imm) goto add; // forced immediate send from overflow
	}else if(!state->unsent_ack_next){
		struct _hv_remote* n = atomic_load_explicit(&_hv_meta.unsent_ack, memory_order_acquire);
		retry: state->unsent_ack_next = n;
		if(!atomic_compare_exchange_weak_explicit(&_hv_meta.unsent_ack, &n, state, memory_order_acq_rel, memory_order_relaxed)) goto retry;
		x_event_queue_wake(&_hv_meta.queue, _HV_SEND_TICK);
	}
}

static void _hv_unencrypt_packet(uint32_t chacha_in[16], uint32_t hi, size_t lo1, struct _hv_send_packet* p){
	chacha_in[12] = -1;
	chacha_in[13] = _hv_lseqof(p, false);
	uint64_t hi1 = (uint64_t)hi<<32|(lo1>>32) + (uint32_t)(chacha_in[13] < (size_t)lo1);
	chacha_in[14] = (uint32_t)(hi1>>32); chacha_in[15] = (uint32_t)hi1;
	unsigned plen = p->len4;
	unsigned j = 5;
	if(p->first){
		uint32_t d[16]; memcpy(d, chacha_in, 64);
		ChaCha20_block(d);
		if(p->kex){
			p->payload4[plen-1] ^= d[15];
			p->payload4[plen-2] ^= d[14];
			j = 9;
		}else{
			p->payload4[plen-1] ^= d[15];
			if((plen & 15) == 13){
				p->payload4[plen-2] ^= d[14];
				p->payload4[plen-3] ^= d[13];
			}
		}
		for(unsigned i = 8; i < 13; i++, j++) p->payload4[j] ^= d[i];
	}
	ChaCha20_block_xor(chacha_in, (uint8_t*)(p->payload4+j), (plen-j)>>4);
}

static bool _hv_filter_send_queue(hivemind_server_t* s, struct _hv_remote* state, uint32_t pipe0[5], uint32_t pipe1[5], bool first, bool bypass){
	uint64_t lo0 = state->send_seq_lo; uint32_t hi = state->send_seq_hi;
	size_t sz = ring_buffer_size(&state->send_queue);
	uint64_t lo1 = lo0 - sz/sizeof(struct _hv_send_packet*);
	if(lo1>lo0) hi--;
	// ACK ERR, filter out bad pipes and make new kEX
	size_t ir = state->unsent_i, i = ir;
	// Trim off all packets with any amount of acks
	while(ir){
		struct _hv_send_packet** s;
		ring_buffer_get(&state->send_queue, ir -= sizeof(s), &s, sizeof(s), true);
		if(!s) break;
		struct _hv_send_packet* p = *s; assert(p);
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
	unsigned header = bypass ? 12 : 20;
	if(first){
		// Shift the first message (which must be the kEX)
		struct _hv_send_packet* p;
		ring_buffer_get(&old_queue, i, &p, sizeof(p), true);
		// We flattened the queue so every entry points to the packet and not the prev
		assert(p && p->first);
		unsigned p_payload_len = lenof(p)-(bypass?16:36);
		size_t len = read_len_inc(p->payload+(bypass?16:36));
		i += sizeof(p);
		free(p);
		while(len > p_payload_len){
			len -= p_payload_len;
			ring_buffer_get(&old_queue, i, &p, sizeof(p), true);
			p_payload_len = lenof(p)-header;
			i += sizeof(p);
			free(p);
		}
	}else for(size_t j = 0; j < i; j += sizeof(struct _hv_send_packet*)){
		struct _hv_send_packet* p;
		ring_buffer_get(&old_queue, j, &p, sizeof(p), true);
		free(p);
	}
	while(i < sz){
		struct _hv_send_packet* p;
		ring_buffer_get(&old_queue, i, &p, sizeof(p), true);
		assert(p); // By waiting for send_unlocked_ref to reach 0 there shouldn't be any blank spots in the unsent section anymore
		unsigned p_payload_len = lenof(p)-header;
		if(!bypass && i < state->unsent_i){
			_hv_unencrypt_packet(chacha_in, hi, lo1, p);
		}
		if(p->first && !_hv_pipeid_in_range((uint32_t*)(p->payload+header), pipe0, pipe1)){
			// Skip entire message
			size_t len = read_len_inc(p->payload+header);
			i += sizeof(p);
			free(p);
			while(len > p_payload_len){
				len -= p_payload_len;
				ring_buffer_get(&old_queue, i, &p, sizeof(p), true);
				p_payload_len = lenof(p)-header;
				i += sizeof(p);
				free(p);
			}
			continue;
		}
		if(!bypass && i < state->unsent_i && p_payload_len > 64){
			chacha_in[12] = 1;
			ChaCha20_block_xor(chacha_in, p->payload+header+64, (p_payload_len>>6)-1);
		}
		if(!qd){
			// First packet, do a new kEX
			struct _hv_send_packet* p2;
			if(bypass){
				p2 = _hv_alloc(sizeof(struct _hv_send_packet) + 80);
				uint64_t shash = _hv_mix64_addr(s->addr, le16toh(s->port_le)), dhash = _hv_mix64_addr(state->addr, state->port);
				*(uint32_t*)p2->payload = htole32(shash); *(uint32_t*)(p2->payload+4) = htole32(shash>>32);
				*(uint32_t*)(p2->payload+8) = htole32(dhash); *(uint32_t*)(p2->payload+16) = htole32(dhash>>32);
				// crcinit is decided deferred (when sent)
				memcpy(p2->payload+16, p->payload+12, p_payload_len < 64 ? p_payload_len : 64);
				if(p_payload_len < 64) memset(p2->payload+16 + p_payload_len, 0, 64 - p_payload_len);
				p2->len4 = 80>>2;
			}else{
				p2 = _hv_alloc(sizeof(struct _hv_send_packet) + 36 + 64);
				_hv_ram_packed_kex(s, (uint32_t*)(p->payload+20), state, (uint32_t*)(p2->payload+16));
				memcpy(p2->payload+56, p->payload+40, 44);
				p2->len4 = (36 + 64)>>2;
			}
			p2->kex = 1; p2->first = 1; p2->resent = 0;
			ring_buffer_push(&state->send_queue, &p2, sizeof(p2), true);
			qd = 1;
			if(p_payload_len > 64){
				// Split into kEX + rest
				memmove(p->payload+header, p->payload+header+64, p_payload_len -= 64);
				p->len4 = p_payload_len>>2; p->first = 0;
				goto reencode;
			}else{
				// everything is included in that packet we just queued
				free(p);
			}
		}else reencode: {
			p->resent = 0;
			*(uint32_t*)(p->payload+(bypass?8:16)) = htole32(qd);
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

static void _hv_send_probe_ack_err(hivemind_server_t* s, uint32_t opts, const remote_t* to){
	uint8_t packet2[80];
	uint32_t* start = (uint32_t*)(packet2+36);
	_hv_nalloc_id(s, start+4);
	start[10] = start[4];
	memcpy(start, s->first_id, 20);
	start[9] = start[0];
	_hv_keyless_packet_finish(s, to, packet2, 40, 2);
}
static void _hv_send_probe_ack_err_enc_bypass(hivemind_server_t* s, uint32_t opts, const remote_t* to){
	uint8_t packet2[61];
	memcpy(packet2+12, s->first_id, 20);
	_hv_nalloc_id(s, (uint32_t*)(packet2+32));
	_hv_crcinitless_packet_finish(s, to, packet2, 40, 2);
}

struct _hv_packet_reassembly{
	size_t total; union{ size_t cur; uint32_t pipe_next; };
	uint32_t pipe_last;
	uint32_t pipe[5];
	uint8_t data[];
};

#if SIZE_MAX > 0xFFFFFFFF
	#define _HV_PACKET_MAX 0x7FFFFFFF
#else
	#define _HV_PACKET_MAX 0x1FFFFFFF
#endif

#define _hv_is_worth_move(plen, buflen) ((plen) >= ((buflen)>>1)+((buflen)>>3))

// size=0 ptr=0 -> None
// size=0 ptr=X -> Reassembly head
// size=N ptr=X -> Saved packet
// size=65535 ptr=0 -> Already received
// size=65535 ptr=N -> Already received dependent packet (fully reassembled, waiting)
// size=65534 ptr=N -> Dependent packet idx
static inline uint8_t* _hv_push_packet(hivemind_server_t* s, struct _hv_remote* state, const remote_t* from, unsigned plen, uint64_t lo, uint32_t hi, uint8_t* p0, unsigned header, unsigned buflen, uint64_t tim, uint64_t msglen, uint32_t pipe_last, bool bypass){
	uint8_t* p = p0 + header;
	size_t idx = lo - state->recv_seq_lo;
	if(idx > _HV_PACKET_MAX) goto done;
	idx *= sizeof(sfat_pointer_t);
	uint32_t lo32 = (uint32_t)lo, next = lo32;
	if(idx >= ring_buffer_size(&state->recv_queue)){
		ring_buffer_push_memset(&state->recv_queue, 0, idx - ring_buffer_size(&state->recv_queue), false);
	}else{
		sfat_pointer_t cur;
		ring_buffer_get(&state->recv_queue, idx, &cur, sizeof(cur), true);
		if(cur){
			if(sfat_size(cur) == 0xFFFE){
				// dependent
				next = (uint32_t)sfat_get(cur);
			}else goto done;
		}
	}
	struct _hv_packet_reassembly* block = 0;
	if(msglen != UINT64_MAX){
		// new message
		if(plen >= msglen){
			msg_complete:
			if(pipe_last == lo32) goto skip_check;
			size_t idx2 = pipe_last - state->recv_seq_lo;
			if(idx2 > _HV_PACKET_MAX) goto skip_check;
			idx2 *= sizeof(sfat_pointer_t);
			if(idx2 >= ring_buffer_size(&state->recv_queue)){
				//assert(false, "pipe_next points forward");
				goto skip_check;
			}
			sfat_pointer_t cur2;
			ring_buffer_get(&state->recv_queue, idx2, &cur2, sizeof(cur2), true);
			unsigned sz = sfat_size(cur2);
			if(sz == 0xFFFF){
				// Already received
				struct _hv_packet_reassembly* dep = (struct _hv_packet_reassembly*)sfat_get(cur2);
				if(dep){
					// dependency
					dep->pipe_next = lo32;
					realloc_and_put:
					if(!block){
						block = _hv_alloc(sizeof(struct _hv_packet_reassembly) + msglen);
						block->total = msglen; block->pipe_next = lo32;
						block->pipe_last = pipe_last;
						memcpy(block->pipe, p-20, 20);
						memcpy(block->data, p, msglen);
					}
					goto trim;
				}//else normal case
			}else if(!sz){
				if(!cur2){
					cur2 = sfat_pack(lo32, 0xFFFE);
					ring_buffer_set(&state->recv_queue, idx2, &cur2, sizeof(cur2), true);
					goto realloc_and_put;
				}//else assert(false);
			}else if(sz < 0xFFFE){
				uint8_t* dep = (uint8_t*)sfat_get(cur2);
				*(uint32_t*)(dep-8) = lo32;
				goto realloc_and_put;
			}
			skip_check:
			// fire msg
			if(!block){
				// directly from packet
				bool move = _hv_is_worth_move(plen, buflen);
				struct _hv_tls_packet_detach d = {.packet_on_heap = move ? ~header : plen};
				_hv_fire_pipe(s, (uint32_t*)(p - 20), p, plen, &d);
				if(move && d.packet_on_heap == SIZE_MAX){
					p0 = malloc(buflen);
				}
			}else{
				// from reassembly completion
				struct _hv_tls_packet_detach d = {.packet_on_heap = ~sizeof(struct _hv_packet_reassembly)};
				_hv_fire_pipe(s, block->pipe, block->data, plen, &d);
				if(d.packet_on_heap != SIZE_MAX) free(block);
			}
			while(next != lo32){
				size_t idx2 = pipe_last - state->recv_seq_lo;
				idx2 *= sizeof(sfat_pointer_t);
				assert(idx2 < ring_buffer_size(&state->recv_queue));
				assert(idx2 > idx);
				ring_buffer_get(&state->recv_queue, idx2, &cur2, sizeof(cur2), true);
				assert(sfat_size(cur2) == 0xFFFF);
				block = sfat_get(cur2);
				struct _hv_tls_packet_detach d = {.packet_on_heap = ~sizeof(struct _hv_packet_reassembly)};
				_hv_fire_pipe(s, block->pipe, block->data, block->total, &d);
				lo32 = next; next = block->pipe_next;
				if(d.packet_on_heap != SIZE_MAX) free(block);
				cur2 = sfat_pack(0, 0xFFFF);
				ring_buffer_set(&state->recv_queue, idx2, &cur2, sizeof(cur2), true);
			}
			trim:
			if(idx){
				sfat_pointer_t cur = sfat_pack(0, 0xFFFF);
				ring_buffer_set(&state->recv_queue, idx, &cur, sizeof(cur), true);
			}else{
				while(true){
					idx += sizeof(sfat_pointer_t);
					sfat_pointer_t cur;
					ring_buffer_set(&state->recv_queue, idx, &cur, sizeof(cur), true);
					if(sfat_size(cur) != 0xFFFF) break;
					assert(!sfat_get(cur));
					if unlikely(sfat_get(cur)) free(sfat_get(cur));
				}
				uint64_t seq_lo = state->send_seq_lo;
				if(state->send_seq_lo = (seq_lo + idx/sizeof(sfat_pointer_t)) < seq_lo) state->send_seq_hi++;
				ring_buffer_shift_discard(&state->recv_queue, idx, false);
			}
		}else{
#if SIZE_MAX < 0xFFFFFFFFFFFF
			if unlikely(len > (SIZE_MAX-sizeof(struct _hv_packet_reassembly))){
				fputs("hivemind: _hv_push_packet(): Message size exhausts user address space", stderr);
				abort();
			}
#endif
			block = _hv_alloc(sizeof(struct _hv_packet_reassembly) + msglen);
			memcpy(block->pipe, p-20, 20);
			memcpy(block->data, p, msglen);
			block->total = msglen; block->cur = 0;
			block->pipe_last = pipe_last;
			sfat_pointer_t cur = sfat_pack(block, 0);
			assert(next == lo32);
			ring_buffer_set(&state->recv_queue, idx, &cur, sizeof(cur), true);
		}
	}else{
		size_t contents = ring_buffer_size(&state->recv_queue);
		if(!idx) goto done;
		sfat_pointer_t cur2;
		ring_buffer_get(&state->recv_queue, idx - sizeof(sfat_pointer_t), &cur2, sizeof(cur2), true);
		unsigned sz = sfat_size(cur2);
		if(!sz){
			block = sfat_get(cur2);
			if(!block) goto add;
			size_t avail = block->total - block->cur, to_add = avail <= plen ? avail : plen;
			memcpy(block->data + block->cur, p, to_add);
			next:
			block->cur += to_add;
			if(idx > sizeof(sfat_pointer_t)){
				sfat_pointer_t cur2 = sfat_pack(0, 0xFFFF);
				ring_buffer_set(&state->recv_queue, idx - sizeof(sfat_pointer_t), &cur2, sizeof(cur2), true);
			}else{
				idx -= sizeof(sfat_pointer_t);
				ring_buffer_shift_discard(&state->recv_queue, sizeof(sfat_pointer_t), true);
				if(!++state->send_seq_lo) state->send_seq_hi++;
			}
			if(avail <= plen){
				block->pipe_next = next;
				pipe_last = block->pipe_last;
				goto msg_complete;
			}else{
				avail -= plen;
				lo32++;
				idx += sizeof(sfat_pointer_t);
				if(idx < contents){
					ring_buffer_get(&state->recv_queue, idx, &cur2, sizeof(cur2), true);
					if(sfat_size(cur2)){
						plen = sfat_size(cur2);
						assert(plen < 0xFFFE);
						to_add = avail <= plen ? avail : plen;
						uint8_t* p2 = sfat_get(cur2);
						next = *(uint32_t*)(p2-4);
						memcpy(block->data + block->cur, p2, to_add);
						free(p2 - header);
						goto next;
					}
				}
			}
			sfat_pointer_t cur = sfat_pack(block, 0);
			ring_buffer_set(&state->recv_queue, idx, &cur, sizeof(cur), true);
		}else add: {
			bool move = _hv_is_worth_move(plen, buflen);
			uint8_t* r = p;
			if(move){
				*(uint32_t*)(p-4) = next;
				p = malloc(buflen);
			}else{
				r = malloc(plen + header) + header;
				*(uint32_t*)(r-4) = next;
				memcpy(r, p, plen);
			}
			sfat_pointer_t cur = sfat_pack(r, plen);
			ring_buffer_set(&state->recv_queue, idx, &cur, sizeof(cur), true);
		}
	}
	done:
	if(DEBUG){
		if unlikely(!lo && !hi) _hv_queue_ack(state, 0, 0, 0, true, bypass);
		else _hv_queue_ack(state, lo, hi, tim, false, bypass);
	}
	_hv_time_lock_rel(&state->recv_last_used, tim);
	return p0;
}

static uint8_t* _hv_drain_reads(hivemind_server_t* s, uint8_t* packet, unsigned buflen, bool original){
	for(unsigned read_count = 0;;){
		remote_t from;
		unsigned plen = (unsigned)x_udp_next_read(s->handle, &from, (char*)packet, buflen);
		if((int)plen < 0) break;
		if(++read_count == 256){
			// Only the original reader should request help
			// quadratic increase is enough, exponential increase is dangerous
			hivemind_server_t* expected = 0;
			if(atomic_compare_exchange_strong_explicit(&_hv_meta.read_help_requested, &expected, s, memory_order_release, memory_order_relaxed)) x_event_queue_wake(&_hv_meta.queue, 0);
			else read_count = 255; // if we fail, we should try again immediately next time
		}
		if(_hv_addr_compare(&from.addr, from.port, &s->addr, le16toh(s->port_le), s->encryption_bypass_prefix_v4, s->encryption_bypass_prefix_v6)){
			// Encryption bypass
			if(plen < 12) continue;
			uint64_t crc = (uint64_t)le32toh(*(uint32_t*)packet)|(uint64_t)le32toh(*(uint32_t*)(packet+4))<<32;
			uint32_t seq = le32toh(*(uint32_t*)(packet+8)), pipe_last = seq;
			unsigned flags = plen&3; plen &= ~3;
			if(flags == 1){
				// ack
				if likely(plen == 12 || packet[12]){
					struct _hv_remote* state = _hv_state_find(s, from.addr, from.port, 0);
					_hv_time_lock_acq(&state->send_last_used);
					uint64_t tim = _hv_internal_clock();
					shared_lock_release(&s->state_lock);
					uint64_t lo0 = state->send_seq_lo; uint32_t hi = state->send_seq_hi;
					size_t sz = ring_buffer_size(&state->send_queue);
					uint64_t lo2 = lo0 - state->packet_offset;
					if(lo2>lo0){ hi--; }; lo0 = lo2;
					_hv_resolve_seq(&lo0, &hi, seq);
					size_t i0 = (lo0 - lo2) * sizeof(struct _hv_send_packet**);
					lo2 += sz/sizeof(struct _hv_send_packet**);
					if(i0 < sz+(128*sizeof(struct _hv_send_packet**))){
						//printf("ack'd [%u,%llu]", hi, lo0);
						*(uint32_t*)(packet+4) = htole32(lo0>>32);
						*(uint32_t*)packet = htole32(hi);
						if(plen > 12 && !packet[plen-4]) plen -= 4;
						if(crc64(state->recv_crcinit, packet, plen) == crc) _hv_ackd(state, packet, plen, tim, lo0, lo2, hi, i0, true);
					}
					_hv_time_lock_rel(&state->send_last_used, tim);
					continue;
				}
				if(plen < 24) continue;
				uint32_t opts = le32toh(*(uint32_t*)(packet+12))>>8;
				uint64_t crcinit = (uint64_t)le32toh(*(uint32_t*)(packet+8)) | (uint64_t)le32toh(*(uint32_t*)(packet+16))<<32;
				uint64_t t = epoch_now()/MILLISECOND_US, t1 = crcinit>>8;
				if((t>t1?t-t1:t1-t) > (s->state_lifetime+999)/MILLISECOND_US)
					continue; // replay
				uint64_t dhash = _hv_mix64_addr(s->addr, le16toh(s->port_le)), shash = _hv_mix64_addr(from.addr, from.port);
				*(uint32_t*)packet = htole32(shash); *(uint32_t*)(packet+4) = htole32(shash>>32);
				*(uint32_t*)(packet+8) = htole32(dhash); *(uint32_t*)(packet+16) = htole32(dhash>>32);
				unsigned payload_len = plen-20-(opts>>23<<2); // high bit set = trunc len by 4 bytes
				if(crc64(crcinit, packet, payload_len) != crc)
					continue; // crc failed
				struct _hv_remote* state = _hv_state_find(s, from.addr, from.port, _HV_FIND_CREATE);
				if(!state) continue;
				uint64_t l = _hv_time_lock_acq(&state->recv_last_used);
				// Prevent replay attack
				if(t1 <= state->key_derived_when){
					_hv_time_lock_rel(&state->recv_last_used, l);
					shared_lock_release(&s->state_lock);
					continue;
				}
				state->key_derived_when = t1;
				_hv_time_lock_rel(&state->recv_last_used, _hv_internal_clock());
				if(opts&2){
					if(payload_len != 40){
						shared_lock_release(&s->state_lock);
						continue;
					}
					// ack err
					_hv_time_lock_acq_excl(&state->send_last_used, &state->send_unlocked_ref);
					shared_lock_release(&s->state_lock);
					bool re_kex = _hv_filter_send_queue(s, state, (uint32_t*)(packet+12), (uint32_t*)(packet+32), opts&1, true);
					_hv_time_lock_rel(&state->send_last_used, re_kex ? 1 : _hv_internal_clock());
				}else if(opts&1) goto probe_ackd;
				else if(!payload_len){
					shared_lock_release(&s->state_lock);
					if(l == 1) _hv_send_probe_ack_err_enc_bypass(s, 2, &from); // probe ack err
					else _hv_crcinitless_packet_finish(s, &from, packet, 0, 1); // probe ack
				}else shared_lock_release(&s->state_lock);
				continue;
			}
			
			unsigned header = 12;
			uint64_t crcinit = 0, len = -1ull;
			if unlikely(flags == 2){
				// New connection requested
				header = 36;
				crcinit = (uint64_t)htole32(*(uint32_t*)(packet+8))|(uint64_t)htole32(*(uint32_t*)(packet+12))<<32;
				uint64_t dhash = _hv_mix64_addr(s->addr, le16toh(s->port_le)), shash = _hv_mix64_addr(from.addr, from.port);
				*(uint32_t*)packet = htole32(shash); *(uint32_t*)(packet+4) = htole32(shash>>32);
				*(uint32_t*)(packet+8) = htole32(dhash); *(uint32_t*)(packet+12) = htole32(dhash>>32);
				if(crc64(crcinit, packet, plen) != crc) continue;
				len = (uint64_t)le16toh(*(uint16_t*)(packet+plen))|(uint64_t)(*(uint32_t*)(packet+plen-4))<<16;
				plen -= 4;
			}else if(flags == 3){
				header = 32;
				len = (uint64_t)le16toh(*(uint16_t*)(packet+plen));
				pipe_last = *(packet+plen+2);
				if(pipe_last == 0xFF){
					len |= (uint64_t)le32toh(*(uint32_t*)(packet+plen-4))<<16;
					pipe_last = le32toh(*(uint32_t*)(packet+plen-8));
					plen -= 8;
				}else pipe_last = seq-pipe_last;
			}

			struct _hv_remote* state = _hv_state_find(s, from.addr, from.port, flags == 2 ? _HV_FIND_CREATE : 0);
			if unlikely(!state) continue;
			uint64_t l = _hv_time_lock_acq(&state->recv_last_used);
			uint64_t tim = _hv_internal_clock();
			shared_lock_release(&s->state_lock);
			uint64_t lo = 0; uint32_t hi = 0;
			size_t idx;
			if likely(flags != 2){
				if(l == 1){
					_hv_time_lock_rel(&state->recv_last_used, l);
					continue;
				}
				crcinit = state->recv_crcinit;
				lo = state->recv_seq_lo; hi = state->recv_seq_hi;
				_hv_resolve_seq(&lo, &hi, seq);
				idx = lo - state->recv_seq_lo;
				if(idx > 0xFFFFFFFF) ack_abort: {
					_hv_queue_ack(state, lo, hi, tim, false, true);
					_hv_time_lock_rel(&state->recv_last_used, tim);
					continue;
				}
				idx *= sizeof(sfat_pointer_t);
				if(idx > 0 && idx < ring_buffer_size(&state->recv_queue)){
					sfat_pointer_t p;
					ring_buffer_get(&state->recv_queue, idx, &p, sizeof(sfat_pointer_t), true);
					if(p) goto ack_abort;
				}
				*(uint32_t*)packet = htole32(hi); *(uint32_t*)(packet+4) = htole32(lo>>32);
			}
			//printf("got %llu\n", lo);
			state->recv_unlocked_ref++;
			_hv_time_lock_rel(&state->recv_last_used, tim);
			if(crc64(crcinit, packet, plen) != crc){
				l = _hv_time_lock_acq(&state->recv_last_used);
				state->recv_unlocked_ref--;
				_hv_time_lock_rel(&state->recv_last_used, l);
				continue; // crc failed
			}
			uint8_t* payload = packet + header; plen -= header;
			l = _hv_time_lock_acq(&state->recv_last_used);
			state->recv_unlocked_ref--;
			if unlikely(flags == 2){
				uint64_t kdw = crcinit>>8;
				uint32_t last[5];
				_hv_nalloc_id(s, last);
				if unlikely(!_hv_pipeid_in_range((uint32_t*)(payload-20), s->first_id, last)){
					// Pipe range test failed, send probe ack err
					_hv_send_probe_ack_err_enc_bypass(s, 3, &from);
					_hv_time_lock_rel(&state->recv_last_used, l);
					continue;
				}else if(kdw <= state->key_derived_when){
					unsigned ackv = state->ack_coal_i;
					state->ack_coal_i = 0;
					_hv_queue_ack(state, 0, 0, 0, true, true);
					state->ack_coal_i = ackv;
					_hv_time_lock_rel(&state->recv_last_used, l);
					continue;
				}
				state->key_derived_when = kdw;
				state->recv_seq_lo = 0; state->recv_seq_hi = 0;
				_hv_remote_cleanup_recv(state, true);
				state->ack_coal_i = 0;
				state->recv_crcinit = crcinit;
				if(!DEBUG) _hv_queue_ack(state, 0, 0, 0, true, true);
			}else if(!DEBUG) _hv_queue_ack(state, lo, hi, tim, false, true);
			if(len != -1ull) header += 20;
			packet = _hv_push_packet(s, state, &from, plen, lo, hi, packet, header, buflen, tim, len, pipe_last, true);
			continue;
		}
		if(plen < 20 || (plen&3)) continue;
		uint32_t seq = le32toh(*(uint32_t*)(packet+16));
		if(plen < 84){
			// ack
			if likely(plen == 20 || packet[20] != 0){
				struct _hv_remote* state = _hv_state_find(s, from.addr, from.port, 0);
				if(!state) continue;
				_hv_time_lock_acq(&state->send_last_used);
				uint64_t tim = _hv_internal_clock();
				shared_lock_release(&s->state_lock);
				uint64_t lo0 = state->send_seq_lo; uint32_t hi = state->send_seq_hi;
				size_t sz = ring_buffer_size(&state->send_queue);
				uint64_t lo2 = lo0 - state->packet_offset;
				if(lo2>lo0){ hi--; }; lo0 = lo2;
				_hv_resolve_seq(&lo0, &hi, seq);

				size_t i0 = (lo0 - lo2) * sizeof(struct _hv_send_packet**);
				lo2 += sz/sizeof(struct _hv_send_packet**);
				if(i0 < sz+(128*sizeof(struct _hv_send_packet**))){
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
					if(!memcmp16(dtag, ptag)) _hv_ackd(state, packet, plen, tim, lo0, lo2, hi, i0, false);
					// else poly failed
				}
				_hv_time_lock_rel(&state->send_last_used, tim);
				continue;
			}
			unsigned payload_len = plen-40;
			uint32_t* knonce = (uint32_t*)(packet+20);
			uint32_t opts = le32toh(*knonce)>>8;
			knonce[0] = *(uint32_t*)(packet+16);
			uint32_t tag[4], *ptag = (uint32_t*)packet;
			uint32_t poly_key[8];
			uint64_t t = epoch_now()/MILLISECOND_US, t1 = _hv_keyless_sig2(s, &from, knonce, poly_key, (uint32_t*)(packet+40), payload_len > 32 ? 8 : payload_len>>2);
			if((t>t1?t-t1:t1-t) > (s->state_lifetime+999)/MILLISECOND_US)
				continue; // replay
			*(uint32_t*)(packet+36) = htole32(opts<<8);
			if(payload_len) Poly1305(packet+36, payload_len+4, (uint8_t*)poly_key, (uint8_t*)tag);
			else memcpy(tag, poly_key, 16);
			if(memcmp16(tag, ptag))
				continue; // sig failed
			struct _hv_remote* state = _hv_state_find(s, from.addr, from.port, _HV_FIND_CREATE);
			if(!state) continue;
			uint64_t l = _hv_time_lock_acq(&state->recv_last_used);
			// Prevent replay attack
			if(t1 <= state->key_derived_when){
				_hv_time_lock_rel(&state->recv_last_used, l);
				shared_lock_release(&s->state_lock);
				continue;
			}
			state->key_derived_when = t1;
			_hv_time_lock_rel(&state->recv_last_used, _hv_internal_clock());
			if(opts&2){
				if(payload_len != 40){
					shared_lock_release(&s->state_lock);
					continue;
				}
				// ack err
				uint32_t pipe0[5]; pipe0[0] = *(knonce+13); memcpy(pipe0+1, knonce+5, 16);
				*(knonce+8) = *(knonce+14);
				_hv_time_lock_acq_excl(&state->send_last_used, &state->send_unlocked_ref);
				shared_lock_release(&s->state_lock);
				bool re_kex = _hv_filter_send_queue(s, state, pipe0, knonce+8, opts&1, false);
				_hv_time_lock_rel(&state->send_last_used, re_kex ? 1 : _hv_internal_clock());
			}else if(opts&1) probe_ackd: {
				// probe ack
				_hv_time_lock_acq(&state->send_last_used);
				shared_lock_release(&s->state_lock);
				state->rtt_gate_lo = state->rtt_gate_hi = 0;
				size_t qsz = ring_buffer_size(&state->send_queue);
				for(size_t i = 0; i < qsz; i += sizeof(struct _hv_send_packet*)){
					struct _hv_send_packet** p;
					ring_buffer_get(&state->send_queue, i, &p, sizeof(p), true);
					if(p) (*p)->resent = 0;
				}
				_hv_time_lock_rel(&state->send_last_used, _hv_internal_clock());
			}else if(!payload_len){
				shared_lock_release(&s->state_lock);
				if(l == 1) _hv_send_probe_ack_err(s, 2, &from); // probe ack err
				else _hv_keyless_packet_finish(s, &from, packet, 0, 1); // probe ack
			}else shared_lock_release(&s->state_lock);
			continue;
		}
		uint32_t chacha_in[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}; // "expand 32-byte k"
		uint64_t kdw = 0, len = -1ull;
		uint32_t pipe_last;
		unsigned header = plen&63, plen2 = plen;
		if unlikely(!header){
			header = 64;
			// New connection requested
			// We should really reject invalid new connections as soon as possible
			// This is what _hv_ram_packed_kex_verify does
			kdw = _hv_ram_packed_kex_verify(s, &from, chacha_in+4, (uint32_t*)(packet+16));
			if(!kdw) continue;
		}
		struct _hv_remote* state = _hv_state_find(s, from.addr, from.port, !!kdw);
		if unlikely(!state) continue;
		uint64_t l = _hv_time_lock_acq(&state->recv_last_used);
		uint64_t tim = _hv_internal_clock();
		shared_lock_release(&s->state_lock);
		uint64_t lo = 0; uint32_t hi = 0;
		size_t idx;
		if likely(!kdw){
			if(l == 1){
				_hv_time_lock_rel(&state->recv_last_used, l);
				continue;
			}
			memcpy(chacha_in+4, state->recv_key, 32);
			lo = state->recv_seq_lo; hi = state->recv_seq_hi;
			_hv_resolve_seq(&lo, &hi, seq);
			idx = lo - state->recv_seq_lo;
			if(idx > 0xFFFFFFFF) ack_abort2: {
				_hv_queue_ack(state, lo, hi, tim, false, false);
				_hv_time_lock_rel(&state->recv_last_used, tim);
				continue;
			}
			idx *= sizeof(sfat_pointer_t);
			if(idx > 0 && idx < ring_buffer_size(&state->recv_queue)){
				sfat_pointer_t p;
				ring_buffer_get(&state->recv_queue, idx, &p, sizeof(sfat_pointer_t), true);
				if(p) goto ack_abort2;
			}
			chacha_in[13] = (uint32_t)lo; chacha_in[14] = (uint32_t)(lo>>32); chacha_in[15] = hi;
		}
		//printf("got %llu\n", lo);
		state->recv_unlocked_ref++;
		_hv_time_lock_rel(&state->recv_last_used, tim);
		uint32_t d[16]; memcpy(d, chacha_in, 64);
		d[12] = 0xFFFFFFFF; ChaCha20_block(d);
		if unlikely(header == 64){
			len = (uint64_t)le32toh(*(uint32_t*)(packet+plen-4) ^ d[15])|(uint64_t)le32toh(*(uint32_t*)(packet+plen-8) ^ d[14])<<32;
			header = 40; plen -= 8;
		}else if(header == 44){
			uint32_t x = le32toh(*(uint32_t*)(packet+plen-4) ^ d[15]);
			len = x>>32; pipe_last = seq-(x&0xFFFF);
			plen -= 4; header = 40;
		}else if(header == 52){
			len = (uint64_t)le32toh(*(uint32_t*)(packet+plen-4) ^ d[15])&0xFFFF|(uint64_t)le16toh(*(uint16_t*)(packet+plen-8) ^ d[14])<<16;
			pipe_last = le32toh(*(uint32_t*)(packet+plen-12) ^ d[13]);
			plen -= 12; header = 40;
		}else if(header != 20) continue;
		uint8_t* payload = packet + header; plen -= header;
		Poly1305(payload, plen2 - header, (uint8_t*) d, (uint8_t*)(d+8));
		uint32_t *ptag = (uint32_t*)packet;
		if(memcmp16(d+8, ptag)){
			l = _hv_time_lock_acq(&state->recv_last_used);
			state->recv_unlocked_ref--;
			_hv_time_lock_rel(&state->recv_last_used, l);
			continue; // poly failed
		}
		chacha_in[12] = 0;
		ChaCha20_block_xor(chacha_in, payload, plen>>6);
		if(len != UINT64_MAX){
			uint32_t* pipeid = (uint32_t*)(payload-20);
			for(unsigned i = 0; i < 5; i++) pipeid[i] ^= d[8+i];
		}
		l = _hv_time_lock_acq(&state->recv_last_used);
		state->recv_unlocked_ref--;
		if unlikely(kdw){
			uint32_t last[5];
			_hv_nalloc_id(s, last);
			if(!_hv_pipeid_in_range((uint32_t*)(payload-20), s->first_id, last)) return -1ull;
			if unlikely(kdw == -1ull){
				// Pipe range test failed, send probe ack err
				_hv_send_probe_ack_err(s, 3, &from);
				_hv_time_lock_rel(&state->recv_last_used, l);
				continue;
			}else if(kdw <= state->key_derived_when){
				unsigned ackv = state->ack_coal_i;
				state->ack_coal_i = 0;
				_hv_queue_ack(state, 0, 0, 0, true, false);
				state->ack_coal_i = ackv;
				_hv_time_lock_rel(&state->recv_last_used, l);
				continue;
			}
			state->key_derived_when = kdw;
			state->recv_seq_lo = 0; state->recv_seq_hi = 0;
			_hv_remote_cleanup_recv(state, false);
			state->ack_coal_i = 0;
			memcpy(state->recv_key, chacha_in+4, 32);
			if(!DEBUG) _hv_queue_ack(state, 0, 0, 0, true, false);
		}else if(!DEBUG) _hv_queue_ack(state, lo, hi, tim, false, false);
		packet = _hv_push_packet(s, state, &from, plen, lo, hi, packet, header, buflen, tim, len, pipe_last, false);
	}
	return packet;
}

static void* _hv_listen(void* _){
#ifdef _POSIX_THREADS
	sigset_t set; sigfillset(&set);
	pthread_sigmask(SIG_BLOCK, &set, 0);
#endif

	struct _hv_thread self = {.hazard = 0};
	self.prevp = &_hv_meta.threads;
	lock_acquire(&_hv_meta.threads_lock, 1);
	struct _hv_thread* next = atomic_load_explicit(&_hv_meta.threads, memory_order_relaxed);
	atomic_init(&self.next, next);
	if(next) next->prevp = &self.next;
	atomic_store_explicit(&_hv_meta.threads, &self, memory_order_release);
	lock_release(&_hv_meta.threads_lock, 1);

	uint8_t* packet = 0; unsigned packetsz = 0;
	for(;;){
		x_event_t ev = x_event_queue_wait(&_hv_meta.queue, -1ull);
		tsan_fence(memory_order_acquire);
		if(ev.type & (X_EVENT_READABLE/*|X_EVENT_WRITABLE*/))
			atomic_store_explicit(&self.hazard, ev.data.ptr, memory_order_relaxed);
		x_event_queue_unlock(&_hv_meta.queue);
		if(ev.type == X_EVENT_WAKE){
			hivemind_server_t* s_s = atomic_load_explicit(&_hv_meta.servers, memory_order_relaxed);
			if unlikely(!s_s){
				x_event_queue_wake(&_hv_meta.queue, 0);
				break;
			}
			hivemind_server_t* help = atomic_load_explicit(&_hv_meta.read_help_requested, memory_order_relaxed);
			if(help){
				retry:
				atomic_store_explicit(&self.hazard, help, memory_order_relaxed);
				//thread_memory_barrier(mb_co_acquire); // order protected by the `acq_rel` xchg
				if(help == atomic_exchange_explicit(&_hv_meta.read_help_requested, 0, memory_order_acq_rel)){
					x_event_queue_wake(&_hv_meta.queue, 0); // someone else deal with any wakes
					ev.data.ptr = help;
					goto recv_packet;
				} // if changed, another wakeup will handle it
			}
			uint64_t wake = GC_FREQ;
			// early test
			uint64_t tim = _hv_internal_clock();
			if(atomic_load_explicit(&_hv_meta.unsent_ack, memory_order_relaxed) > (struct _hv_remote*)1){
				struct _hv_remote* state = atomic_exchange_explicit(&_hv_meta.unsent_ack, 0, memory_order_acquire), *head = state, **prev = &head;
				new_unsent_acks:
				while(state > (struct _hv_remote*)1){
					uint64_t l = _hv_time_lock_acq(&state->recv_last_used);
					struct _hv_remote* n = state->unsent_ack_next;
					if(!state->ack_coal_i) goto rem;
					if((((tim<<8) - (state->ack_coal_tim0<<8)) >> 8) >= _HV_SEND_TICK){
						_hv_queue_ack(state, state->recv_seq_lo, state->recv_seq_hi, 0, true, state->bypass_type == 1);
						rem:
						*prev = n;
						state->unsent_ack_next = 0;
						if unlikely(!state->prevp){
							uint64_t l = _hv_time_lock_try_acq(&state->send_last_used);
							if(l){
								if(!state->undrained_next){ free(state); goto next_a; }
								else _hv_time_lock_rel(&state->send_last_used, l);
							}
						}
					}else prev = &state->unsent_ack_next;
					_hv_time_lock_rel(&state->recv_last_used, l);
					next_a: state = n;
				}
				state = 0;
				if(!atomic_compare_exchange_strong_explicit(&_hv_meta.unsent_ack, &state, head, memory_order_relaxed, memory_order_acquire)){
					*prev = state;
					goto new_unsent_acks;
				}
				if(head > (struct _hv_remote*)1) wake = _HV_SEND_TICK;
			}
			// early test
			if(atomic_load_explicit(&_hv_meta.undrained, memory_order_relaxed) > (struct _hv_remote*)1){
				struct _hv_remote* state = atomic_exchange_explicit(&_hv_meta.undrained, 0, memory_order_acquire), *head = state, **prev = &head;
				new_undraineds:
				while(state > (struct _hv_remote*)1){
					uint64_t l = _hv_time_lock_acq(&state->send_last_used);
					uint64_t tim = _hv_internal_clock();
					struct _hv_remote* n = state->undrained_next;
					if(!state->packet_offset){
						*prev = n;
						state->undrained_next = 0;
						if unlikely(!state->prevp){
							uint64_t l = _hv_time_lock_try_acq(&state->recv_last_used);
							if(l){
								if(!state->unsent_ack_next){ free(state); goto next_u; }
								else _hv_time_lock_rel(&state->recv_last_used, l);
							}
						}
					}else{
						tim = _hv_drain_writes(state, tim, state->bypass_type&1);
						prev = &state->undrained_next;
					}
					_hv_time_lock_rel(&state->send_last_used, tim);
					next_u: state = n;
				}
				state = 0;
				if(!atomic_compare_exchange_strong_explicit(&_hv_meta.undrained, &state, head, memory_order_relaxed, memory_order_acquire)){
					*prev = state;
					goto new_undraineds;
				}
				if(head > (struct _hv_remote*)1) wake = _HV_SEND_TICK;
			}
			uint64_t last_gc = atomic_load_explicit(&_hv_meta.last_gc, memory_order_relaxed);
			if unlikely(s_s && last_gc != -1ull && tim - last_gc > GC_FREQ && atomic_compare_exchange_strong_explicit(&_hv_meta.last_gc, &last_gc, -1ull, memory_order_acquire, memory_order_relaxed)){
				for(;;){
					atomic_store_explicit(&self.hazard, s_s, memory_order_relaxed);
					thread_memory_barrier(mb_co_acquire);
					hivemind_server_t* s2 = atomic_load_explicit(&_hv_meta.servers, memory_order_acquire);
					if(s2 == s_s) break;
				}
				while(s_s){
					_hv_remove_unused(s_s, tim);
					atomic_store_explicit(&self.hazard, (void*)-1ull, memory_order_relaxed);
					thread_memory_barrier(mb_co_acquire);
					s_s = atomic_load_explicit(&s_s->next, memory_order_acquire);
					atomic_store_explicit(&self.hazard, s_s, memory_order_release);
					thread_memory_barrier(mb_co_acquire);
				}
				atomic_store_explicit(&_hv_meta.last_gc, _hv_internal_clock(), memory_order_release);
			}
			x_event_queue_wake(&_hv_meta.queue, wake);
			continue;
		}
		if(ev.type & X_EVENT_READABLE) recv_packet: {
			hivemind_server_t* s = (hivemind_server_t*) ev.data.ptr;
			atomic_thread_fence(memory_order_acquire);
			uint16_t mtu = le16toh(s->mtu_le);
			if(packetsz < mtu){
				free(packet);
				packet = (uint8_t*) _hv_alloc(packetsz = mtu);
			}
			packet = _hv_drain_reads(s, packet, packetsz, ev.type == X_EVENT_READABLE);
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
			struct _hv_open_close_data* oc = s->oc;
			if(!oc) continue;
			atomic_compare_exchange_strong_explicit(&_hv_meta.read_help_requested, &expected, 0, memory_order_relaxed, memory_order_relaxed);
			lock_acquire(&_hv_meta.threads_lock, 1);
			hivemind_server_t* next = atomic_load_explicit(&s->next, memory_order_relaxed);
			atomic_store_explicit(s->prevp, next, memory_order_relaxed);
			if(next) next->prevp = s->prevp;
			else if(s->prevp == &_hv_meta.servers)
				x_event_queue_wake(&_hv_meta.queue, 0);
			lock_release(&_hv_meta.threads_lock, 1);

			_hv_hazard_wait(s);
			while(atomic_load_explicit(&s->vq_flag, memory_order_relaxed)){
				atomic_wait(&s->vq_flag, 1);
			}
			exclusive_lock_wait(&s->state_lock);
			// Server should be unreachable after this

			// Fearless freeing!
			_hv_finish(s, oc->finish_cb, oc->filename[0] ? oc->filename : 0);
			void (*on_close)(void*) = oc->cb;
			free(oc);
			
			// Safe to teardown
			x_socket_free(s->handle);
			s->handle = X_SOCKET_INVALID;
			if(on_close) on_close(s->udata);
		}
	}
	free(packet);
	lock_acquire(&_hv_meta.threads_lock, 1);
	next = atomic_load_explicit(&self.next, memory_order_relaxed);
	if(next) next->prevp = self.prevp;
	atomic_store_explicit(self.prevp, next, memory_order_release);
	lock_release(&_hv_meta.threads_lock, 1);
	return 0;
}

static void* _hv_vq_loop(hivemind_server_t* s){
	struct _hv_vq* b = s->vq_block;
	for(;;){
		vqueue_block_t msg = vqueue_wait(&b->q);
		if(msg.size >= 20){
			struct _hv_tls_packet_detach d = {.packet_on_heap = msg.size, .vq_block = b};
			_hv_fire_pipe(s, (uint32_t*)msg.data, msg.data+20, msg.size-20, &d);
			if(d.packet_on_heap == SIZE_MAX)
				continue;
		}
		vqueue_free(&b->q, msg);
		if(!msg.size) break;
	}
	if(atomic_fetch_sub_explicit(&b->ref, 1, memory_order_acquire) == 1){
		vqueue_close(&b->q);
		free(b);
	}
	atomic_store_explicit(&s->vq_flag, 0, memory_order_release);
	atomic_wake(&s->vq_flag, 1);
	return 0;
}