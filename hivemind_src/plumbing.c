#include "internals.c"

struct _buf_being_built{
	array_buffer_t buf;
	size_t sz0;
};
thread_local struct{
	size_t packet_on_heap;
	union{ lock_t* pipe_lock; struct _buf_being_built* buf_being_built; };
} tls;
static bool _pipeid_in_range(const uint32_t test[5], const uint32_t b0[5], const uint32_t b1[5]){
	uint64_t tn = (uint64_t)le32toh(test[0])<<24|((uint64_t)le32toh(test[1])&0xFFFFFF);
	uint64_t t0 = (uint64_t)le32toh(b0[0])<<24|((uint64_t)le32toh(b0[1])&0xFFFFFF);
	uint64_t t1 = (uint64_t)le32toh(b1[0])<<24|((uint64_t)le32toh(b1[1])&0xFFFFFF);
	if(tn < t0 || tn > t1) return false;
	uint64_t hin = (uint64_t)(le32toh(test[1])>>24)<<32 | (uint64_t)le32toh(test[2]);
	uint64_t hi0 = (uint64_t)(le32toh(b0[1])>>24)<<32 | (uint64_t)le32toh(b0[2]);
	uint64_t hi1 = (uint64_t)(le32toh(b1[1])>>24)<<32 | (uint64_t)le32toh(b1[2]);
	if(hin < hi0 || hin > hi1) return false;
	uint64_t lon = (uint64_t)le32toh(test[3])<<32 | (uint64_t)le32toh(test[4]);
	if(hin == hi0){
		uint64_t lo0 = (uint64_t)le32toh(b0[3])<<32 | (uint64_t)le32toh(b0[4]);
		if(lon < lo0) return false;
	}
	if(hin == hi1){
		uint64_t lo1 = (uint64_t)le32toh(b1[3])<<32 | (uint64_t)le32toh(b1[4]);
		if(lon >= lo1) return false;
	}
	return true;
}

static bool _fire_pipe(hivemind_server_t* s, const uint32_t id[5], const uint8_t* data, size_t len){
	uint64_t hash = _mix64((uint64_t)id[1]<<32|id[4])^_mix64((uint64_t)id[2]<<32|id[3]);
	shared_lock_acquire(&s->pipes_lock);
	uint32_t bexp = s->pipes_bucket_exp;
	if(!bexp){
		shared_lock_release(&s->pipes_lock);
		return false;
	}
	struct _hivemind_pipe* p = (struct _hivemind_pipe*) atomic_load_explicit(&s->pipes_data[hash&((1<<bexp)-1)], memory_order_acquire);
	while(p){
		if(p->id[0]==id[0] && p->id[1]==id[1] && p->id[2]==id[2] && p->id[3]==id[3] && p->id[4]==id[4])
			break;
		p = (struct _hivemind_pipe*)(atomic_load_explicit(&p->next, memory_order_acquire)&-2ull);
	}
	if(p && lock_try_acquire(tls.pipe_lock = &p->ref, 1)){
		s->on_msg(s->udata, data, len, p->udata);
		if(tls.pipe_lock) lock_release(tls.pipe_lock, 1);
	}
	shared_lock_release(&s->pipes_lock);
	return true;
}

static void _append_pipe(hivemind_server_t* s, uint32_t id[5], void* udata){
	bool excl = false;
	retry:
	shared_lock_acquire(&s->pipes_lock);
	size_t b = (1<<s->pipes_bucket_exp)&-2ull; // 1 => 0
	size_t i = atomic_fetch_add_explicit(&s->pipes_heap_i, 1, memory_order_acquire);
	if(i >= b){
		if(i > b){
			shared_lock_release(&s->pipes_lock);
			thread_yield();
			goto retry;
		}
		size_t ob = b;
		if(!excl && !shared_lock_upgrade(&s->pipes_lock)){
			goto retry;
		}
		excl = true;
		if(!b){
			s->pipes_data = (atomic(uintptr_t)*) _hivemind_alloc(sizeof(atomic(uintptr_t))*2 + sizeof(struct _hivemind_pipe)*4);
			atomic_init(&s->pipes_data[0], 0);
			atomic_init(&s->pipes_data[1], 0);
			b = 2;
		}else{
			b <<= 1;
			uintptr_t* data2 = (uintptr_t*) _hivemind_alloc((sizeof(atomic(uintptr_t)) + sizeof(struct _hivemind_pipe)*2) * b);
			struct _hivemind_pipe* oh = (struct _hivemind_pipe*)(s->pipes_data+ob);
			struct _hivemind_pipe* nh = (struct _hivemind_pipe*)(data2+b);
			memset(data2, 0, sizeof(struct _hivemind_pipe*)*b);
			size_t j = 0;
			for(size_t i = 0; i < ob; i++){
				if(atomic_load_explicit(&oh[i].next, memory_order_relaxed)&1) continue;
				uint64_t hash = _mix64((uint64_t)oh[i].id[1]<<32|oh[i].id[4])^_mix64((uint64_t)oh[i].id[2]<<32|oh[i].id[3]);
				nh[j].next = data2[hash&(b-1)];
				memcpy(nh[j].id, oh[i].id, 20);
				nh[j].udata = oh[i].udata;
				atomic_init(&nh[j].ref, 1);
				data2[hash&(b-1)] = (uintptr_t)(nh+i);
				j++;
			}
			free(s->pipes_data);
			s->pipes_data = (atomic(uintptr_t)*) data2;
			i = j; atomic_init(&s->pipes_heap_i, j+1);
		}
		s->pipes_bucket_exp++;
	}
	if(excl) exclusive_lock_downgrade(&s->pipes_lock);
	uint64_t hash = _mix64((uint64_t)id[1]<<32|id[4])^_mix64((uint64_t)id[2]<<32|id[3]);
	struct _hivemind_pipe* p = (struct _hivemind_pipe*)(s->pipes_data+b) + i;

	p->next = atomic_load_explicit(&s->pipes_data[hash&(b-1)], memory_order_relaxed);
	while(!atomic_compare_exchange_weak_explicit(&s->pipes_data[hash&(b-1)], (uintptr_t*)&p->next, (uintptr_t)p, memory_order_acq_rel, memory_order_relaxed));
	memcpy(p->id, id, 20);
	atomic_init(&p->ref, 1);
	p->udata = udata;
	shared_lock_release(&s->pipes_lock);
}

static void* _kill_pipe(hivemind_server_t* s, const uint32_t id[5]){
	uint64_t hash = _mix64((uint64_t)id[1]<<32|id[4])^_mix64((uint64_t)id[2]<<32|id[3]);
	shared_lock_acquire(&s->pipes_lock);
	size_t b = (1<<s->pipes_bucket_exp)&-2ull; // 1 => 0
	void* d = 0;
	if(b){
		atomic(uintptr_t)* op = &s->pipes_data[hash&(b-1)];
		struct _hivemind_pipe* p = (struct _hivemind_pipe*) atomic_load_explicit(op, memory_order_acquire);
		while(p){
			if(p->id[0]==id[0] && p->id[1]==id[1] && p->id[2]==id[2] && p->id[3]==id[3] && p->id[4]==id[4])
				break;
			p = (struct _hivemind_pipe*)(atomic_load_explicit(op = &p->next, memory_order_acquire)&-2ull);
		}
		if(p){
			d = p->udata;
			uintptr_t next2 = atomic_fetch_or_explicit(&p->next, 1, memory_order_acq_rel);
			if(next2&1){ d = 0; goto end; } // pipe already deleted
			retry:
			if(op < s->pipes_data+b){
				// New nodes might be inserted here since this is the beginning
				uintptr_t pv = (uintptr_t)p;
				if(!atomic_compare_exchange_strong_explicit(op, &pv, next2, memory_order_release, memory_order_relaxed)) do{
					op = &((struct _hivemind_pipe*) pv)->next;
					pv = atomic_load_explicit(op, memory_order_acquire)&-2ull;
				}while(pv != (uintptr_t)p);
			}else atomic_store_explicit(op, next2, memory_order_release);
			if(next2){
				next2 = atomic_load_explicit(&((struct _hivemind_pipe*)next2)->next, memory_order_acquire);
				if(next2&1){
					next2 -= 1;
					goto retry;
				}
			}
			lock_acquire(&p->ref, 1);
			p->udata = 0;
			size_t deleted = atomic_fetch_add_explicit(&s->deleted_pipes, 1, memory_order_relaxed)+1;
			if(b == 2 && deleted == 4){
				// TODO: trim down to remove old deleted pipes
				// however this could be a deadlock hazard against a size increase
				if(!shared_lock_try_upgrade(&s->pipes_lock)){
					// Someone else is already cleaning up (upgrade fail guarantees an exclusive lock is already being acquired, and all paths that do that also clean up old pipes)
					goto end;
				}
				free(s->pipes_data);
				s->pipes_data = 0;
				atomic_init(&s->pipes_heap_i, 0);
				s->pipes_bucket_exp = b = 0;
				exclusive_lock_downgrade(&s->pipes_lock);
			}else if(deleted == (b*3>>1)){
				if(!shared_lock_try_upgrade(&s->pipes_lock)){
					// Someone else is already cleaning up (upgrade fail guarantees an exclusive lock is already being acquired, and all paths that do that also clean up old pipes)
					goto end;
				}
				size_t ob = b; b >>= 1;
				uintptr_t* data2 = (uintptr_t*) _hivemind_alloc((sizeof(atomic(uintptr_t)) + sizeof(struct _hivemind_pipe)*2) * b);
				struct _hivemind_pipe* oh = (struct _hivemind_pipe*)(s->pipes_data+ob);
				struct _hivemind_pipe* nh = (struct _hivemind_pipe*)(data2+b);
				memset(data2, 0, sizeof(struct _hivemind_pipe*)*b);
				size_t j = 0;
				for(size_t i = 0; i < ob; i++){
					if(atomic_load_explicit(&oh[i].next, memory_order_relaxed)&1) continue;
					uint64_t hash = _mix64((uint64_t)oh[i].id[1]<<32|oh[i].id[4])^_mix64((uint64_t)oh[i].id[2]<<32|oh[i].id[3]);
					nh[j].next = data2[hash&(b-1)];
					memcpy(nh[j].id, oh[i].id, 20);
					nh[j].udata = oh[i].udata;
					atomic_init(&nh[j].ref, 1);
					data2[hash&(b-1)] = (uintptr_t)(nh+i);
					j++;
				}
				free(s->pipes_data);
				s->pipes_data = (atomic(uintptr_t)*) data2;
				atomic_init(&s->pipes_heap_i, j);
				s->pipes_bucket_exp--;
				exclusive_lock_downgrade(&s->pipes_lock);
			}
		}
	}
	end:
	shared_lock_release(&s->pipes_lock);
	return d;
}

static inline void _keyless_sig(hivemind_server_t* s, const remote_t* from, uint32_t knonce[5], uint32_t* out_tag, uint32_t* out_xor, unsigned xor_count){
	assert(xor_count <= 8);
	_alloc_id(s, knonce, epoch_now()/MILLISECOND_US);
	uint32_t chacha[16] = {0x2d6d6172, 0x6b636170, 0x6b206465, 0x68637865}; // "ram-packed kexch"
	memcpy(chacha+4, s->master_key, 32);
	for(unsigned i = 0; i < 4; i++) chacha[i+2] ^= le32toh(s->addr.dwords[i]);
	for(unsigned i = 0; i < 4; i++) chacha[i+6] ^= le32toh(from->addr.dwords[i]);
	chacha[10] ^= (uint32_t)(le16toh(s->port_le)<<16|from->port);
	chacha[11] ^= le32toh(knonce[0]);
	for(unsigned i = 0; i < 4; i++) chacha[12+i] = le32toh(knonce[i+1]);
	ChaCha20_block(chacha);
	memcpy(out_tag, chacha, 32);
	if(out_xor) for(unsigned i = 0; i < xor_count; i++) out_xor[i] ^= chacha[i+8];
}
static inline uint64_t _keyless_sig2(hivemind_server_t* s, const remote_t* from, const uint32_t knonce[restrict 5], uint32_t out_tag[restrict 8], uint32_t* restrict out_xor, unsigned xor_count){
	uint32_t chacha[16] = {0x2d6d6172, 0x6b636170, 0x6b206465, 0x68637865}; // "ram-packed kexch"
	memcpy(chacha+4, s->master_key, 32);
	for(unsigned i = 0; i < 4; i++) chacha[i+2] ^= le32toh(from->addr.dwords[i]);
	for(unsigned i = 0; i < 4; i++) chacha[i+6] ^= le32toh(s->addr.dwords[i]);
	chacha[10] ^= (uint32_t)(from->port<<16|le16toh(s->port_le));
	chacha[11] ^= le32toh(knonce[0]);
	for(unsigned i = 0; i < 4; i++) chacha[12+i] = le32toh(knonce[i+1]);
	ChaCha20_block(chacha);
	memcpy(out_tag, chacha, 32);
	if(out_xor) for(unsigned i = 0; i < xor_count; i++) out_xor[i] ^= chacha[i+8];
	return (uint64_t)le32toh(knonce[0])<<24|(uint64_t)(le32toh(knonce[1])&0xFFFFFF);
}

static void _ram_packed_kex(hivemind_server_t* s, const uint32_t pipeid[restrict 5], struct _hivemind_remote* state, uint32_t out_packet[restrict 10]){
	for(unsigned i = 0; i < 5; i++) out_packet[i+5] = pipeid[i];
	_keyless_sig(s, &state->remote, out_packet, state->send_key, out_packet+5, 5);
}

static uint64_t _ram_packed_kex_verify(hivemind_server_t* s, const remote_t* from, uint32_t out_key[restrict 8], const uint32_t in_packet[restrict 5], uint32_t pipeid[restrict 5]){
	uint64_t t = epoch_now()/MILLISECOND_US, t1 = _keyless_sig2(s, from, in_packet, out_key, pipeid, 5);
	if((t>t1?t-t1:t1-t) > (s->state_lifetime+999)/MILLISECOND_US) return 0;
	uint32_t last[5];
	_nalloc_id(s, last);
	if(!_pipeid_in_range(pipeid, s->first_id, last)) return -1ull;
#ifndef HIVEMIND_NO_RECV_TSF
#ifdef THREAD_SPECULATION_FENCE_AVAILABLE
	thread_speculation_fence();
#elif !defined(WNO_THREAD_SFENCE_MISSING) // to be supplied via -D
	#warning Thread speculation fence unavailable on this architecture
#endif
#endif
	return t1;
}

static inline void _split_by_hash(struct _hivemind_remote *p, struct _hivemind_remote** out, size_t buckets){
	struct _hivemind_remote *pl = 0, *pr = 0;
	while(p){
		struct _hivemind_remote *np = p->next;
		uint64_t hash = _mix64_addr(p->addr, p->port);
		if(hash&buckets){ p->next = pr; pr = p; }
		else{ p->next = pl; pl = p; }
		p = np; // !!!
	}
	out[0] = pl; out[buckets] = pr;
}

static struct _hivemind_remote* _hivemind_state_find(hivemind_server_t* s, ip_addr_t addr, uint16_t port, bool create){
	uint64_t hash = _mix64_addr(addr, port);
	shared_lock_acquire(&s->state_lock);
	bool has_excl = false;
	retry: {}
	struct _hivemind_remote** state = s->remote_buckets;
	size_t buckets = (1<<s->buckets_exp&-2ull)>>1;
	struct _hivemind_remote* p;
	if(!buckets){
		if(!create) cr_fail: {
			shared_lock_release(&s->state_lock);
			return NULL;
		}
		shared_lock_upgrade(&s->state_lock);
		if(!(state = s->remote_buckets))
			s->buckets_exp = buckets = 1;
		goto init;
	}
	// For just one bucket (up to 4 remotes) save an allocation
	if(buckets > 1){ p = state[hash&(buckets-1)]; }
	else p = (struct _hivemind_remote*) state;
	while(p){
		if(!memcmp(&p->addr, &addr, 16) && p->port == port){
			if(has_excl) exclusive_lock_downgrade(&s->state_lock);
			return p;
		}
		p = p->next;
	}
	if(!create) goto cr_fail;
	// Not found
	if(!has_excl){
		shared_lock_upgrade(&s->state_lock);
		has_excl = true;
		goto retry;
	}
	if((s->remote_count++) == (buckets<<1)){
		size_t bytes = sizeof(struct _hivemind_remote*) * (buckets<<1);
		struct _hivemind_remote** state2 = (struct _hivemind_remote**) _hivemind_alloc(bytes);
		s->buckets_exp++;
		memset(state2, 0, bytes);
		if(buckets > 1){
			for(size_t i = 0; i < buckets; i++)
				_split_by_hash(state[i], state2+i, buckets);
		}else _split_by_hash((struct _hivemind_remote*) state, state2, 1);
		free(s->remote_buckets); s->remote_buckets = state = state2;
		buckets <<= 1;
	}
	init:
	p = (struct _hivemind_remote*) _hivemind_alloc_a(sizeof(struct _hivemind_remote), alignof(struct _hivemind_remote));
	memset(p, 0, sizeof(*p));
	p->handle = s->handle;
	// For just one bucket (up to 4 remotes) save an allocation
	struct _hivemind_remote** onext = buckets > 1 ? &state[hash&(buckets-1)] : (struct _hivemind_remote**) &s->remote_buckets, *next = *onext;
	p->next = next; if(next) next->prevp = &p->next;
	*(p->prevp = onext) = p;
	p->addr = addr; p->port = port; p->server_mtu = le16toh(s->mtu_le);
	// 0.1us = ~10MB/s = ~80Mbps
	p->us_per_byte = .1f;
	p->min_latency = INFINITY;
	p->avg_latency = 500000;
	atomic_init(&p->send_last_used, 1);
	atomic_init(&p->recv_last_used, 1);
	p->send_order_end = &p->send_order_start;
	p->server = s;
	exclusive_lock_downgrade(&s->state_lock);
	return p;
} //Callee must shared_lock_release(&s->state_lock) when done

static size_t read_len_inc(const uint8_t* payload){
	size_t len = le16toh(*(uint16_t*)(payload+20));
	if(len&1){
		len = (len>>1 | (uint64_t)le16toh(*(uint16_t*)(payload+22))<<15 | (uint64_t)le16toh(*(uint16_t*)(payload+24))<<31) + 27;
	}else len = (len>>1)+22;
	return len;
}

static void encrypt_packet(uint32_t state[16], struct _send_packet* p){
	uint8_t* pl = p->payload+20;
	state[12] = 0;
	if(p->len_p&1){
		pl += 16;
		uint32_t pipeid[5];
		memcpy(pipeid, pl, 20);
		ChaCha20_block_xor(state, pl, p->len_p>>1);
		memcpy(pl, pipeid, 20);
	}else ChaCha20_block_xor(state, pl, p->len_p>>1);
	uint32_t d[16]; memcpy(d, state, 64);
	// RFC 7539 § 2.3-2.4 recommends using in[12] ==0 for AEAD, >0 for payload, and in[13-15] for nonce
	// One slight change is we use in[12] ==2^32-1 for AEAD and 0..<2^32-1 for payload. This is a stylistic choice
	// and has no effect on the quality of the resulting keystream. Individual UDP packets will never be able to surpass block counter > 1024
	d[12] = 0xFFFFFFFF;
	ChaCha20_block(d);
	Poly1305(pl, (size_t)(p->len_p>>1)<<6, (uint8_t*)d, p->payload);
}

static inline bool addr_compare(ip_addr_t* a, uint16_t ap, ip_addr_t* b, uint16_t bp, uint8_t mv4, uint8_t mv6){
	if(!(a->dwords[0] | a->dwords[1] | (le32toh(a->words[2])^0xffff0000))){
		if(b->dwords[0] | b->dwords[1] | (le32toh(b->words[2])^0xffff0000)) return false;
		// ipv4
		if(mv4 >= 32){
			if((ap^bp)>>(48-mv4)) return false;
			return a->dwords[3] == b->dwords[3];
		}
		return !(mv4 && (be32toh(a->dwords[3] ^ b->dwords[3]) >> (32 - mv4)));
	}
	// ipv6
	if(mv6 >= 128){
		if((ap^bp)>>(144-mv6)) return false;
		return !memcmp16(a->dwords, b->dwords);
	}
	if(mv6 >= 8 && memcmp(a, b, mv6>>3)) return false;
	if((mv6&7) && ((a->bytes[mv6>>3] ^ b->bytes[mv6>>3]) >> (8-mv6))) return false;
	return true;
}

#define _KEYLESS_PACKET_SIZE(n) 40+((n+3)&-4)
#define _KEYLESS_PACKET_OFF 40

static inline void _keyless_packet_finish(hivemind_server_t* s, const remote_t* to, uint8_t* packet, unsigned payload_len, uint32_t opts){
	uint32_t poly_key[8];
	_keyless_sig(s, to, (uint32_t*)(packet+20), poly_key, (uint32_t*)(packet+40), payload_len > 32 ? 32 : payload_len>>2);
	*(uint32_t*)(packet+16) = *(uint32_t*)(packet+20); *(uint32_t*)(packet+20) = htole32(opts<<8);
	uint32_t tmp = *(uint32_t*)(packet+36); *(uint32_t*)(packet+36) = opts;
	Poly1305(packet+36, payload_len+4, (uint8_t*)poly_key, packet);
	*(uint32_t*)(packet+36) = tmp;
	bool send_success = x_udp_send(s->handle, *to, (char*)packet, payload_len+40);
	soft_assert(send_success);
}

#define _CRCINITLESS_PACKET_SIZE(n) 24+((n+3)&-8)
#define _CRCINITLESS_PACKET_OFF 20

static inline void _crcinitless_packet_finish(hivemind_server_t* s, const remote_t* to, uint8_t* packet, unsigned payload_len, uint32_t opts){
	uint64_t shash = _mix64_addr(s->addr, le16toh(s->port_le)), dhash = _mix64_addr(to->addr, to->port);
	*(uint32_t*)packet = htole32(shash); *(uint32_t*)(packet+4) = htole32(shash>>32);
	*(uint32_t*)(packet+8) = htole32(dhash); *(uint32_t*)(packet+16) = htole32(dhash>>32);
	if((payload_len-1)&4){
		opts |= 0x800000;
		*(uint32_t*)(packet+20+payload_len) = 0;
	}
	*(uint32_t*)(packet+12) = htole32(opts<<8);
	uint64_t id = _alloc_id_short(s), crc = crc64(id, packet, payload_len);
	*(uint32_t*)(packet+8) = htole32(id); *(uint32_t*)(packet+16) = htole32(id>>32);	
	*(uint32_t*)packet = htole32(crc); *(uint32_t*)(packet+4) = htole32(crc>>32);
	bool send_success = x_udp_send(s->handle, *to, (char*)packet, payload_len + (opts>>23<<2));
	soft_assert(send_success);
}