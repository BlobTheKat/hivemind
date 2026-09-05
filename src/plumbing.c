#include "internals.c"
#define CHACHA20_POLY1305_IMPL
#include "chacha20poly1305.h"
#define CRC64_IMPL
#include "crc64.h"

struct _hv_tls_buf_being_built{
	array_buffer_t buf;
	size_t sz0;
};
struct _hv_tls_packet_detach{
	size_t packet_on_heap;
	struct _hv_vq* vq_block;
	lock_t* pipe_lock;
};
thread_local union{ struct _hv_tls_packet_detach* packet_detach; struct _hv_tls_buf_being_built* buf_being_built; } tls;
static bool _hv_pipeid_in_range(const uint32_t test[5], const uint32_t b0[5], const uint32_t b1[5]){
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

static bool _hv_fire_pipe(hivemind_server_t* s, const uint32_t id[5], const uint8_t* data, size_t len, struct _hv_tls_packet_detach* d){
	uint64_t hash = _hv_mix64((uint64_t)id[1]<<32|id[4])^_hv_mix64((uint64_t)id[2]<<32|id[3]);
	shared_lock_acquire(&s->pipes_lock);
	uint32_t bexp = s->pipes_bucket_exp;
	if(!bexp){
		shared_lock_release(&s->pipes_lock);
		return false;
	}
	struct _hv_pipe* p = (struct _hv_pipe*) atomic_load_explicit(&s->pipes_data[hash&((1<<bexp)-1)], memory_order_acquire);
	while(p){
		if(!memcmp(p->id, id, 20))
			break;
		p = (struct _hv_pipe*)(atomic_load_explicit(&p->next, memory_order_acquire)&-2ull);
	}
	if(p && lock_try_acquire(d->pipe_lock = &p->ref, 1)){
		tls.packet_detach = d;
		s->on_msg(s->udata, data, len, p->udata);
		if(d->pipe_lock) lock_release(d->pipe_lock, 1);
	}
	shared_lock_release(&s->pipes_lock);
	return true;
}

static void _hv_append_pipe(hivemind_server_t* s, uint32_t id[5], void* udata){
	if(!udata) return;
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
			s->pipes_data = (atomic(uintptr_t)*) _hv_alloc(sizeof(atomic(uintptr_t))*2 + sizeof(struct _hv_pipe)*4);
			atomic_init(&s->pipes_data[0], 0);
			atomic_init(&s->pipes_data[1], 0);
			b = 2;
		}else{
			b <<= 1;
			uintptr_t* data2 = (uintptr_t*) _hv_alloc((sizeof(atomic(uintptr_t)) + sizeof(struct _hv_pipe)*2) * b);
			struct _hv_pipe* oh = (struct _hv_pipe*)(s->pipes_data+ob);
			struct _hv_pipe* nh = (struct _hv_pipe*)(data2+b);
			memset(data2, 0, sizeof(struct _hv_pipe*)*b);
			size_t j = 0;
			for(size_t i = 0; i < ob; i++){
				if(atomic_load_explicit(&oh[i].next, memory_order_relaxed)&1) continue;
				uint64_t hash = _hv_mix64((uint64_t)oh[i].id[1]<<32|oh[i].id[4])^_hv_mix64((uint64_t)oh[i].id[2]<<32|oh[i].id[3]);
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
	uint64_t hash = _hv_mix64((uint64_t)id[1]<<32|id[4])^_hv_mix64((uint64_t)id[2]<<32|id[3]);
	struct _hv_pipe* p = (struct _hv_pipe*)(s->pipes_data+b) + i;

	p->next = atomic_load_explicit(&s->pipes_data[hash&(b-1)], memory_order_relaxed);
	while(!atomic_compare_exchange_weak_explicit(&s->pipes_data[hash&(b-1)], (uintptr_t*)&p->next, (uintptr_t)p, memory_order_acq_rel, memory_order_relaxed));
	memcpy(p->id, id, 20);
	atomic_init(&p->ref, 1);
	p->udata = udata;
	shared_lock_release(&s->pipes_lock);
}

static void* _hv_kill_pipe(hivemind_server_t* s, const uint32_t id[5]){
	uint64_t hash = _hv_mix64((uint64_t)id[1]<<32|id[4])^_hv_mix64((uint64_t)id[2]<<32|id[3]);
	shared_lock_acquire(&s->pipes_lock);
	size_t b = (1<<s->pipes_bucket_exp)&-2ull; // 1 => 0
	void* d = 0;
	if(b){
		atomic(uintptr_t)* op = &s->pipes_data[hash&(b-1)];
		struct _hv_pipe* p = (struct _hv_pipe*) atomic_load_explicit(op, memory_order_acquire);
		while(p){
			if(!memcmp(p->id, id, 20))
				break;
			p = (struct _hv_pipe*)(atomic_load_explicit(op = &p->next, memory_order_acquire)&-2ull);
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
					op = &((struct _hv_pipe*) pv)->next;
					pv = atomic_load_explicit(op, memory_order_acquire)&-2ull;
				}while(pv != (uintptr_t)p);
			}else atomic_store_explicit(op, next2, memory_order_release);
			if(next2){
				next2 = atomic_load_explicit(&((struct _hv_pipe*)next2)->next, memory_order_acquire);
				if(next2&1){
					next2 -= 1;
					goto retry;
				}
			}
			lock_acquire(&p->ref, 1);
			p->udata = 0;
			size_t deleted = atomic_fetch_add_explicit(&s->deleted_pipes, 1, memory_order_relaxed)+1;
			if(b == 2 && deleted == 4){
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
				uintptr_t* data2 = (uintptr_t*) _hv_alloc((sizeof(atomic(uintptr_t)) + sizeof(struct _hv_pipe)*2) * b);
				struct _hv_pipe* oh = (struct _hv_pipe*)(s->pipes_data+ob);
				struct _hv_pipe* nh = (struct _hv_pipe*)(data2+b);
				memset(data2, 0, sizeof(struct _hv_pipe*)*b);
				size_t j = 0;
				for(size_t i = 0; i < ob; i++){
					if(atomic_load_explicit(&oh[i].next, memory_order_relaxed)&1) continue;
					uint64_t hash = _hv_mix64((uint64_t)oh[i].id[1]<<32|oh[i].id[4])^_hv_mix64((uint64_t)oh[i].id[2]<<32|oh[i].id[3]);
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

static inline void _hv_keyless_sig(hivemind_server_t* s, const remote_t* from, uint32_t knonce[5], uint32_t* out_tag, uint32_t* out_xor, unsigned xor_count){
	assert(xor_count <= 8);
	_hv_alloc_id(s, knonce, epoch_now()/MILLISECOND_US);
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
static inline uint64_t _hv_keyless_sig2(hivemind_server_t* s, const remote_t* from, const uint32_t knonce[static restrict 5], uint32_t out_tag[static restrict 8], uint32_t* restrict out_xor, unsigned xor_count){
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

static void _hv_ram_packed_kex(hivemind_server_t* s, const uint32_t pipeid[static restrict 5], struct _hv_remote* state, uint32_t out_packet[static restrict 5]){
	remote_t to = {.addr = state->addr, .port = state->port};
	_hv_keyless_sig(s, &to, out_packet, state->send_key, 0, 0);
}

static uint64_t _hv_ram_packed_kex_verify(hivemind_server_t* s, const remote_t* from, uint32_t out_key[static restrict 8], const uint32_t in_packet[static restrict 5]){
	uint64_t t = epoch_now()/MILLISECOND_US, t1 = _hv_keyless_sig2(s, from, in_packet, out_key, 0, 0);
	if((t>t1?t-t1:t1-t) > (s->state_lifetime+999)/MILLISECOND_US) return 0;
#ifndef HIVEMIND_NO_RECV_TSF
#ifdef THREAD_SPECULATION_FENCE_AVAILABLE
	thread_speculation_fence();
#elif !defined(WNO_THREAD_SFENCE_MISSING) // to be supplied via -D
	#warning Thread speculation fence unavailable on this architecture
#endif
#endif
	return t1;
}

static inline bool _hv_addr_compare(const ip_addr_t* a, uint16_t ap, const ip_addr_t* b, uint16_t bp, uint8_t mv4, uint8_t mv6){
	if(!(a->dwords[0] | a->dwords[1] | (le32toh(a->words[2])^0xffff0000))){
		if(b->dwords[0] | b->dwords[1] | (le32toh(b->words[2])^0xffff0000)) return false;
		// ipv4
		if(mv4 >= 32){
			if(mv4 > 48 || (ap^bp)>>(48-mv4)) return false;
			return a->dwords[3] == b->dwords[3];
		}
		return !(mv4 && (be32toh(a->dwords[3] ^ b->dwords[3]) >> (32 - mv4)));
	}
	// ipv6
	if(mv6 >= 128){
		if(mv6 > 144 || (ap^bp)>>(144-mv6)) return false;
		return !memcmp16(a->dwords, b->dwords);
	}
	if(mv6 >= 8 && memcmp(a, b, mv6>>3)) return false;
	if((mv6&7) && ((a->bytes[mv6>>3] ^ b->bytes[mv6>>3]) >> (8-mv6))) return false;
	return true;
}

static inline void _hv_split_by_hash(struct _hv_remote *p, struct _hv_remote** out, size_t buckets){
	struct _hv_remote *pl = 0, *pr = 0;
	while(p){
		struct _hv_remote *np = p->next;
		uint64_t hash = _hv_mix64_addr(p->addr, p->port);
		if(hash&buckets){ p->next = pr; if(pr) pr->prevp = &p->next; pr = p; }
		else{ p->next = pl; if(pl) pl->prevp = &p->next; pl = p; }
		p = np; // !!!
	}
	out[0] = pl; out[buckets] = pr;
	if(pl) pl->prevp = &out[0];
	if(pr) pr->prevp = &out[buckets];
}

static inline void _hv_vq_name(char name[56], ip_addr_t addr, uint16_t port){
	const char set[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
	memcpy(name, "hivemind_", 9);
	for(unsigned i = 0, j = 9; i < 8; i++, j += 5){
		uint16_t v = be16toh(addr.words[i]);
		name[j] = set[(v>>12)&15]; name[j+1] = set[(v>>8)&15];
		name[j+2] = set[(v>>4)&15]; name[j+3] = set[v&15];
		name[j+4] = '_';
	}
	name[49] = set[(port>>12)&15]; name[50] = set[(port>>8)&15];
	name[51] = set[(port>>4)&15]; name[52] = set[port&15];
	name[53] = '.'; name[54] = 'v'; name[55] = 'q';
}

#define _HV_FIND_CREATE 1
#define _HV_FIND_INCLUDE_VQ 2
static struct _hv_remote* _hv_state_find(hivemind_server_t* s, ip_addr_t addr, uint16_t port, uint8_t expect){
	uint64_t hash = _hv_mix64_addr(addr, port);
	shared_lock_acquire(&s->state_lock);
	bool has_excl = false, use_vq;
	retry: {}
	struct _hv_remote** state = s->remote_buckets;
	size_t buckets = (1<<s->buckets_exp&-2ull)>>1;
	struct _hv_remote* p;
	if(!buckets){
		if(!(expect&_HV_FIND_CREATE)) fail: {
			shared_lock_release(&s->state_lock);
			return NULL;
		}
		use_vq = _hv_addr_compare(&addr, port, &s->addr, le16toh(s->port_le), s->network_bypass_prefix_v4, s->network_bypass_prefix_v6);
		if(use_vq && !(expect&_HV_FIND_INCLUDE_VQ)) goto fail;
		shared_lock_upgrade(&s->state_lock);
		if(!(state = s->remote_buckets))
			s->buckets_exp = buckets = 1;
		goto init;
	}
	// For just one bucket (up to 4 remotes) save an allocation
	if(buckets > 1){ p = state[hash&(buckets-1)]; }
	else p = (struct _hv_remote*) state;
	while(p){
		if(!memcmp(&p->addr, &addr, 16) && p->port == port){
			if(has_excl) exclusive_lock_downgrade(&s->state_lock);
			if((p->bypass_type&2) && !(expect&_HV_FIND_INCLUDE_VQ)) goto fail;
			return p;
		}
		p = p->next;
	}
	if(!(expect&_HV_FIND_CREATE)) goto fail;
	// Not found
	if(!has_excl){
		has_excl = true;
		use_vq = _hv_addr_compare(&addr, port, &s->addr, le16toh(s->port_le), s->network_bypass_prefix_v4, s->network_bypass_prefix_v6);
		if(use_vq && !(expect&_HV_FIND_INCLUDE_VQ)) goto fail;
		if(!shared_lock_upgrade(&s->state_lock)) goto retry;
	}

	if((s->remote_count++) == (buckets<<1)){
		size_t bytes = sizeof(struct _hv_remote*) * (buckets<<1);
		struct _hv_remote** state2 = (struct _hv_remote**) _hv_alloc(bytes);
		s->buckets_exp++;
		memset(state2, 0, bytes);
		if(buckets > 1){
			for(size_t i = 0; i < buckets; i++)
				_hv_split_by_hash(state[i], state2+i, buckets);
		}else _hv_split_by_hash((struct _hv_remote*) state, state2, 1);
		free(s->remote_buckets); s->remote_buckets = state = state2;
		buckets <<= 1;
	}
	init: {}
	// For just one bucket (up to 4 remotes) save an allocation
	struct _hv_remote** onext = buckets > 1 ? &state[hash&(buckets-1)] : (struct _hv_remote**) &s->remote_buckets, *next = *onext;
	if(use_vq){
		p = (struct _hv_remote*) _hv_alloc(sizeof(struct _hv_remote_vq));
		struct _hv_remote_vq* p_vq = (struct _hv_remote_vq*) p;
		memset(p_vq, 0, sizeof(*p_vq));
		const char set[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
		char name[56]; _hv_vq_name(name, addr, port);
		p_vq->bypass_type = 2 + vqueue_open(&p_vq->q, name, sizeof(name));
		p_vq->prevp = onext;
	}else{
		p = (struct _hv_remote*) _hv_alloc_a(_HV_REMOTE_SIZE, alignof(struct _hv_remote));
		memset(p, 0, sizeof(*p));
		p->server_mtu = le16toh(s->mtu_le)>>2;
		p->bypass_type = _hv_addr_compare(&addr, port, &s->addr, le16toh(s->port_le), s->encryption_bypass_prefix_v4, s->encryption_bypass_prefix_v6);
		// 0.1us = ~10MB/s = ~80Mbps
		p->us_per_byte = .1f;
		p->min_latency = INFINITY;
		p->avg_latency = 500000;
		atomic_init(&p->send_last_used, 1);
		atomic_init(&p->recv_last_used, 1);
		p->send_order_end = &p->send_order_start;
		p->server = s;
		p->prevp = onext;
#if SIZEOF_X_HANDLE <= 4
		p->handle = s->handle;
#endif
	}
	*onext = p;
	p->next = next;
	if(next){
		if(next->bypass_type&2) ((struct _hv_remote_vq*)next)->prevp = &p->next;
		else next->prevp = &p->next;
	}
	p->addr = addr; p->port = port;
	exclusive_lock_downgrade(&s->state_lock);
	return p;
} //Callee must shared_lock_release(&s->state_lock) when done

static void _hv_encrypt_packet(uint32_t chacha[16], struct _hv_send_packet* p){
	unsigned hdr = 5+(p->kex<<2);
	uint32_t* pl = p->payload4 + hdr;
	chacha[12] = 0;
	chacha[13] = le32toh(p->payload4[3]);
	chacha[14] = le32toh(p->payload4[1]);
	chacha[15] = le32toh(p->payload4[0]);

	uint32_t d[16]; memcpy(d, chacha, 64);
	// RFC 7539 § 2.3-2.4 recommends using in[12] ==0 for AEAD, >0 for payload, and in[13-15] for nonce
	// One slight change is we use in[12] ==2^32-1 for AEAD and 0..<2^32-1 for payload. This is a stylistic choice
	// and has no effect on the quality of the resulting keystream. Individual UDP packets will never be able to surpass block counter > 1024
	d[12] = 0xFFFFFFFF;
	ChaCha20_block(d);

	if(p->first){
		uint32_t* pipeid = pl;
		for(unsigned i = 0; i < 5; i++) pipeid[i] ^= d[8+i];
		pl += 5;
	}
	unsigned num_blocks = (p->len4-5)>>4;
	ChaCha20_block_xor(chacha, (uint8_t*)pl, num_blocks);
	pl += num_blocks<<6;
	uint32_t* end = p->payload4+p->len4;
	for(unsigned i = 15; pl < end;) *--end ^= d[i];
	
	Poly1305((uint8_t*)pl, (size_t)((p->len4-hdr)<<2), (uint8_t*)d, (uint8_t*)(p->payload4+hdr));
}

static inline void _hv_keyless_packet_finish(hivemind_server_t* s, const remote_t* to, uint8_t* packet, unsigned payload_len, uint32_t opts){
	uint32_t poly_key[8];
	_hv_keyless_sig(s, to, (uint32_t*)(packet+20), poly_key, (uint32_t*)(packet+40), payload_len > 32 ? 32 : payload_len>>2);
	*(uint32_t*)(packet+16) = *(uint32_t*)(packet+20); *(uint32_t*)(packet+20) = htole32(opts<<8);
	uint32_t tmp = *(uint32_t*)(packet+36); *(uint32_t*)(packet+36) = opts;
	Poly1305(packet+36, payload_len+4, (uint8_t*)poly_key, packet);
	*(uint32_t*)(packet+36) = tmp;
	bool send_success = x_udp_send(s->handle, *to, (char*)packet, payload_len+40);
	soft_assert(send_success);
}

static inline void _hv_crcinitless_packet_finish(hivemind_server_t* s, const remote_t* to, uint8_t* packet, unsigned payload_len, uint32_t opts){
	uint64_t shash = _hv_mix64_addr(s->addr, le16toh(s->port_le)), dhash = _hv_mix64_addr(to->addr, to->port);
	*(uint32_t*)packet = htole32(shash); *(uint32_t*)(packet+4) = htole32(shash>>32);
	*(uint32_t*)(packet+8) = htole32(dhash); *(uint32_t*)(packet+16) = htole32(dhash>>32);
	*(uint32_t*)(packet+12) = htole32(opts<<8);
	uint64_t id = _hv_alloc_id_short(s), crc = crc64(id, packet, payload_len);
	*(uint32_t*)(packet+8) = htole32(id); *(uint32_t*)(packet+16) = htole32(id>>32);	
	*(uint32_t*)packet = htole32(crc); *(uint32_t*)(packet+4) = htole32(crc>>32);
	bool send_success = x_udp_send(s->handle, *to, (char*)packet, payload_len + 1);
	soft_assert(send_success);
}

void _hv_add_to_send_pipe(struct _hv_remote* state, const uint32_t id[5], struct _hv_send_packet* nfirst, struct _hv_send_packet** nlast, size_t dwords, struct _hv_send_packet_placeholder* plch){
	uint64_t hash = _hv_mix64((uint64_t)id[1]<<32|id[4])^_hv_mix64((uint64_t)id[2]<<32|id[3]);
	void *pos = hash_table_find(&state->pipes_with_unsent_b, hash), *pos0 = pos;
	struct _hv_send_pipe* pipe_state;
	check:
	assert(pos);
	char* unsent_data = array_buffer_data(&state->pipes_with_unsent);
	pipe_state = (struct _hv_send_pipe*)(unsent_data + (size_t)pos) - 1;
	if(memcmp(id, pipe_state->id, 20)){
		pos = pipe_state->next;
		goto check;
	}
	pipe_state->queued += dwords;
	*plch->prevp = nfirst;
	*nlast = plch->next;
	if((uintptr_t)plch->next & 1){
		struct _hv_send_packet_placeholder* p2 = (struct _hv_send_packet_placeholder*)((uintptr_t)plch->next-1);
		p2->prevp = nlast;
	}
	if(array_buffer_size(&state->pipes_with_unsent) > sizeof(struct _hv_send_pipe)){
		if(state->unsent_iter_i == (size_t)pos){
			state->unsent_iter_i = 0;
		}else if(state->unsent_iter_i && ((struct _hv_send_pipe*)(unsent_data + state->unsent_iter_i) - 1)->queued > pipe_state->queued){
			state->unsent_iter_i = (size_t)pos;
		}
	}else state->unsent_iter_i = sizeof(struct _hv_send_pipe);
}
uint32_t _hv_find_pipe_last(struct _hv_remote* state, const hivemind_pipe_t* pipe, uint32_t self, struct _hv_send_packet_placeholder* plch){
	uint64_t hash = _hv_mix64((uint64_t)pipe->id[1]<<32|pipe->id[4])^_hv_mix64((uint64_t)pipe->id[2]<<32|pipe->id[3]);
	void *pos = hash_table_find(&state->pipes_with_unsent_b, hash), *pos0 = pos;
	struct _hv_send_pipe* pipe_state;
	check:
	if(!pos){
		pipe_state = array_buffer_push_garbage(&state->pipes_with_unsent, sizeof(struct _hv_send_pipe));
		memcpy(pipe_state->id, pipe->id, 20);
		pipe_state->start = 0;
		pipe_state->end = &pipe_state->start;
		pipe_state->dependency_lo = 0xFFFFFFFF00000000;
		pipe_state->dependency_hi = 0xFFFFFFFF;
		pipe_state->queued = (size_t)le16toh(pipe->mtu_le) << (sizeof(size_t)*CHAR_BIT-2);
		unsigned cur_rank = hash_table_rank(&state->pipes_with_unsent_b);
		size_t sz = array_buffer_size(&state->pipes_with_unsent);
		if(sz > sizeof(struct _hv_send_pipe)*2 << cur_rank){
			// rehash
			char* data = (char*) array_buffer_data(&state->pipes_with_unsent);
			hash_table_set_rank(&state->pipes_with_unsent_b, ++cur_rank);
			for(unsigned i = 0; i < sz; i += sizeof(struct _hv_send_pipe)){
				struct _hv_send_pipe* ps = (struct _hv_send_pipe*)(data+i);
				uint64_t hash2 = _hv_mix64((uint64_t)ps->id[1]<<32|ps->id[4])^_hv_mix64((uint64_t)ps->id[2]<<32|ps->id[3]);
				ps->next = hash_table_find(&state->pipes_with_unsent_b, hash2);
				hash_table_put(&state->pipes_with_unsent_b, hash2, (void*)(i + sizeof(struct _hv_send_pipe)));
			}
			pos0 = hash_table_find(&state->pipes_with_unsent_b, hash);
		}
		pipe_state->next = pos0;
		hash_table_put(&state->pipes_with_unsent_b, hash, (void*)array_buffer_size(&state->pipes_with_unsent));
	}else{
		pipe_state = (struct _hv_send_pipe*)(array_buffer_data(&state->pipes_with_unsent) + (size_t)pos) - 1;
		if(memcmp(pipe->id, pipe_state->id, 20)){
			pos = pipe_state->next;
			goto check;
		}
	}
	struct _hv_send_packet* tagged = (struct _hv_send_packet*)((char*)plch+1);
	*pipe_state->end = tagged;
	plch->prevp = pipe_state->end;
	plch->next = 0;
	pipe_state->end = &plch->next;
#ifdef __SIZEOF_INT128__
	unsigned __int128 cur = ((__int128)state->send_seq_lo | (__int128)state->send_seq_hi<<64);
	unsigned __int128 last = ((__int128)pipe_state->dependency_lo | (__int128)pipe_state->dependency_hi<<64);
	return cur-last < 0x80000000 ? (uint32_t)pipe_state->dependency_lo : self;
#else
	bool small_diff = state->send_seq_lo-pipe_state->dependency_lo < 0x80000000;
	if(pipe_state->dependency_hi == state->send_seq_hi-1 && pipe_state->dependency_lo < state->send_seq_lo) small_diff = false;
	return small_diff ? (uint32_t)pipe_state->dependency_lo : self;
#endif
}
#if SIZEOF_X_HANDLE <= 4
	#define _hv_state_handle(s) (s)->handle
#else
	#define _hv_state_handle(s) (s)->server->handle
#endif