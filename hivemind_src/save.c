#define _HIVEMIND_SAVE_HEADER_SZ 96
#include "plumbing.c"

static inline uint64_t _read64(const uint8_t* p){
	return (uint64_t)p[0]<<56|(uint64_t)p[1]<<48|(uint64_t)p[2]<<40|(uint64_t)p[3]<<32|(uint64_t)p[4]<<24|(uint64_t)p[5]<<16|(uint64_t)p[6]<<8|(uint64_t)p[7];
}
static inline void _write64(uint8_t* p, uint64_t x){
	p[0] = (uint8_t)(x>>56); p[1] = (uint8_t)(x>>48); p[2] = (uint8_t)(x>>40); p[3] = (uint8_t)(x>>32);
	p[4] = (uint8_t)(x>>24); p[5] = (uint8_t)(x>>16); p[6] = (uint8_t)(x>>8); p[7] = (uint8_t)x;
}
static inline uint32_t _read32(const uint8_t* p){
	return (uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|(uint32_t)p[3];
}
static inline void _write32(uint8_t* p, uint32_t x){
	p[0] = (uint8_t)(x>>24); p[1] = (uint8_t)(x>>16); p[2] = (uint8_t)(x>>8); p[3] = (uint8_t)x;
}

static inline bool _hivemind_load(hivemind_server_t* s, uint8_t* data, size_t sz, void* (*pipe_restore)(void*,uint8_t*,size_t)){
	// Poly1305 checksum. By using the master key as the poly tag, we can verify the master key hasn't changed, without storing it or a hash of it in the file. Very cool
	uint32_t tag[4], mkey[8];
	for(unsigned i = 0; i < 8; i++) mkey[i] = htole32(s->master_key[i]);
	Poly1305(data+16, sz-16, (uint8_t*)mkey, (uint8_t*)tag);
	if(memcmp16(tag, data)) return false;

	// Reserved
	if(_read32(data+16)) return false;

	uint64_t pipec = _read64(data+20), remc = _read64(data+28);

	hivemind_pipe_t* p0 = (hivemind_pipe_t*)(data+36);
	if(memcmp(p0->dwords, s->dwords, 16)) return false;
	if(p0->port_le != s->port_le || le16toh(p0->mtu_le) < le16toh(s->mtu_le)) return false;
	memcpy(s->first_id, p0->id, 20);

	uint64_t tim = epoch_now() / MILLISECOND_US;
	uint32_t* id1 = (uint32_t*)(data+76);
	uint64_t t1 = le32toh(id1[0])<<24 | (le32toh(id1[1])&0xFFFFFF);
	if(tim<t1) return false;
	uint64_t hi = (uint64_t)le32toh(id1[1])>>24<<32 | (uint64_t)le32toh(id1[2]);
	uint64_t lo = (uint64_t)le32toh(id1[3])<<32 | (uint64_t)le32toh(id1[4]);

	uint8_t* p = data+_HIVEMIND_SAVE_HEADER_SZ, *end = data + sz;

	while(pipec--){
		// Let's not complicate things, this is good enough
		if(p+28 > end) break;
		uint64_t sz = _read64(p+20);
		uint8_t* p2 = p+28+((sz+3ull)&~3ull);
		if(p2 > end) break;
		_append_pipe(s, (uint32_t*)p, pipe_restore(s->udata, p+28, sz));
		p = p2;
	}

	while(remc--){
		if(p+20 > end) break;
		ip_addr_t addr; memcpy(addr.bytes, p, 16);
		uint32_t x = _read32(p+16);
		struct _hivemind_remote* state = _hivemind_state_find(s, addr, (uint16_t)x, true);
		p += 20;
		bool r = x>>16&1, w = x>>17&1;
		uint8_t* pw = p+68;
		if(r){
			if(p+68 > end || atomic_load_explicit(&state->recv_last_used, memory_order_relaxed) > 1) break;
			for(unsigned i = 0; i < 8; i++) state->recv_key[i] = _read32(p+i*4);
			uint64_t rl = _read64(p+32);
			if(rl>1) atomic_store_explicit(&state->recv_last_used, rl, memory_order_relaxed);
			state->recv_seq_hi = _read32(p+40);
			state->recv_seq_lo = _read64(p+44);
			size_t rsz = _read64(p+52);
			state->key_derived_when = _read64(p+60);
			p += 68 + w*68;
			if(!rsz) goto next;
			size_t szab = _read64(p);
			if(szab){
				state->cur_packet = _hivemind_alloc(szab);
				size_t sza = _read64(p+8);
				memcpy(state->cur_packet, p+16, sza);
				state->cur_packet_left = szab - sza;
				sfat_pointer_t p0 = sfat_pack(state->cur_packet + sza, 0);
				ring_buffer_push(&state->recv_queue, &p0, sizeof(p0), true);
				p += 16+sza;
			}else{
				p += 8;
				if(rsz > 1) ring_buffer_push_memset(&state->recv_queue, 0, sizeof(sfat_pointer_t), true);
			}
			rsz--;
			for(; rsz; rsz--){
				unsigned sz = _read32(p);
				uint8_t* p2 = 0;
				if(sz){
					p2 = malloc(sz);
					memcpy(p2, p+4, sz);
				}
				sfat_pointer_t p0 = sfat_pack(p2, sz);
				ring_buffer_push(&state->recv_queue, &p0, sizeof(p0), true);
				p += sz+4;
			}
		}
		next:
		if(w){
			if(pw+68 > end || atomic_load_explicit(&state->send_last_used, memory_order_relaxed) > 1) break;
			for(unsigned i = 0; i < 8; i++) state->send_key[i] = _read32(pw+i*4);
			uint64_t sl = _read64(pw+32);
			if(sl) atomic_store_explicit(&state->send_last_used, sl, memory_order_relaxed);
			state->send_seq_hi = _read32(pw+40);
			state->send_seq_lo = _read64(pw+44);
			size_t wsz = _read64(pw+52) * sizeof(struct _send_packet*);
			uint32_t tmp = _read32(pw+60);
			memcpy(&state->avg_latency, &tmp, sizeof(tmp));
			tmp = _read32(pw+64);
			memcpy(&state->us_per_byte, &tmp, sizeof(tmp));
			state->growth = -1.f;

			uint64_t lo0 = state->send_seq_lo - wsz;
			for(; wsz; wsz--){
				unsigned sz = _read32(p);
				struct _send_packet* p2 = 0;
				if(sz){
					p2 = malloc(sizeof(struct _send_packet) + sz + 16);
					p2->first = sz>>16; p2->resent = 0; p2->len_p = (sz+16)>>5;
#if SIZE_MAX == UINT64_MAX
					p2->seq_m = lo0>>32;
#endif
					memcpy(p2->payload+16, p+4, sz);
				}
				p += 4+sz;
				lo0++;
				ring_buffer_push(&state->send_queue, &p2, sizeof(p2), true);
			}
		}
		shared_lock_release(&s->state_lock);
	}

#ifdef __SIZEOF_INT128__
	s->_id = (uint128_t)hi<<64 | (uint128_t)lo;
#else
	s->_id_hi = hi; s->_id_lo = lo;
#endif
	return true;
}

static inline void _hivemind_finish(hivemind_server_t* s, void (*pipe_finish)(void*,void*), const char* save){
	struct _buf_being_built b;
	size_t pipe_top = atomic_load_explicit(&s->pipes_heap_i, memory_order_relaxed);
	size_t pipec = pipe_top - atomic_load_explicit(&s->deleted_pipes, memory_order_relaxed);
	if(save){
		uint8_t* header = array_buffer_push_garbage(&b.buf, _HIVEMIND_SAVE_HEADER_SZ);

		_write32(header+16, 0); // Reserved
		_write64(header+20, pipec); _write64(header+28, s->remote_count);

		memcpy(header+36, s->dwords, 20); // addr/port/mtu
		memcpy(header+56, s->first_id, 20);
		_nalloc_id(s, (uint32_t*)(header+76));
	}

	struct _hivemind_pipe* pheap = (struct _hivemind_pipe*)(s->pipes_data + ((1ull<<s->pipes_bucket_exp)&-2ull));
	tls.buf_being_built = save ? &b : 0;
	for(size_t i = 0; i < pipe_top; i++){
		struct _hivemind_pipe* p = pheap+i;
		if(atomic_load_explicit(&p->next, memory_order_relaxed)&1ull){
			// deleted
			pipec++;
			continue;
		}
		if(save){
			memcpy(array_buffer_push_garbage(&b.buf, 28), p->id, 20);
			b.sz0 = array_buffer_size(&b.buf);
			if(pipe_finish) pipe_finish(s->udata, p->udata);
			size_t sz = array_buffer_size(&b.buf) - b.sz0;
			_write64((uint8_t*)array_buffer_data(&b.buf)+b.sz0+20, sz);
			if(sz&3) array_buffer_push_garbage(&b.buf, 4-(sz&3));
		}else if(pipe_finish) pipe_finish(s->udata, p->udata);
	}
	if(save) tls.buf_being_built = 0;
	assert(pipec == pipe_top);
	free(s->pipes_data);
	atomic_init(&s->pipes_heap_i, 0);
	atomic_init(&s->deleted_pipes, 0);
	s->pipes_data = 0;
	s->pipes_bucket_exp = 0;


	size_t buckets = (1<<s->buckets_exp)>>1;
	struct _hivemind_remote** r = s->remote_buckets;
	if(buckets < 2) r = (struct _hivemind_remote**) &s->remote_buckets;
	uint64_t t = _hivemind_internal_clock(), life = s->state_lifetime;
	for(size_t i = 0; i < buckets; i++){
		struct _hivemind_remote* state = r[i];
		while(state){
			uint64_t rl = _time_lock_acq(&state->recv_last_used);
			uint64_t sl = _time_lock_acq(&state->send_last_used);
			assert(!state->recv_unlocked_ref && !state->send_unlocked_ref);
			state->ack_coal_i = 0;
			if(save){
				// Save: { Send, Recv } { Buffer, Seq, Last used } + Read KDW + Write RQR state
				bool r = rl!=1&&(t>life+life?rl>=t-life-life:true), w = sl!=1&&(t>life?sl>=t-life:true);
				uint8_t* head = array_buffer_push_garbage(&b.buf, r*68+w*68+20);
				memcpy(head, state->addr.bytes, 16);
				_write32(head+16, (uint32_t)(state->port|w<<16|r<<17)); head += 20; // Upper 14 bits reserved
				size_t rsz = state->recv_queue.size, wsz = state->send_queue.size;
				if(r){
					for(unsigned i = 0; i < 8; i++) _write32(head+i*4, state->recv_key[i]);
					_write64(head+32, rl);
					_write32(head+40, state->recv_seq_hi);
					_write64(head+44, state->recv_seq_lo);
					_write64(head+52, rsz / sizeof(sfat_pointer_t));
					_write64(head+60, state->key_derived_when);
					head += 68;
				}
				if(w){
					for(unsigned i = 0; i < 8; i++) _write32(head+i*4, state->send_key[i]);
					_write64(head+32, sl);
					_write32(head+40, state->send_seq_hi);
					_write64(head+44, state->send_seq_lo);
					_write64(head+52, wsz / sizeof(struct _send_packet*));
					uint32_t tmp; memcpy(&tmp, &state->avg_latency, sizeof(tmp));
					_write32(head+60, tmp);
					memcpy(&tmp, &state->us_per_byte, sizeof(tmp));
					_write32(head+64, tmp);
				}
				if(r){
					if(state->cur_packet){
						sfat_pointer_t p0;
						ring_buffer_get(&state->recv_queue, 0, &p0, sizeof(p0), true);
						size_t sza = (size_t)(state->cur_packet - sfat_get(p0)), szb = state->cur_packet_left;
						uint8_t* p2 = array_buffer_push_garbage(&b.buf, sza+16);
						_write64(p2, sza+szb); _write64(p2+8, sza);
						memcpy(p2, state->cur_packet, sza);
					}else if(rsz) array_buffer_push_memset(&b.buf, 0, 8);
					ring_iterator_t it = ring_buffer_iterator(&state->recv_queue, sizeof(sfat_pointer_t), -1ull);
					assert(it.remaining == rsz - sizeof(sfat_pointer_t));
					sfat_pointer_t p;
					while(ring_iterator_next(&it, &p, sizeof(p), true)){
						if(!sfat_get(p)){
							array_buffer_push_memset(&b.buf, 0, 4);
							continue;
						}
						unsigned sz = sfat_size(p);
						uint8_t* p2 = array_buffer_push_garbage(&b.buf, sz+4);
						_write32(p2, sz); // Upper 16 bits reserved
						memcpy(p2+4, sfat_get(p), sz);
					}
				}
				if(w){
					uint32_t chacha_in[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}; // "expand 32-byte k"
					memcpy(chacha_in+4, state->send_key, 32);
					ring_iterator_t it = ring_buffer_iterator(&state->send_queue, 0, -1ull);
					assert(it.remaining == wsz);
					struct _send_packet* p;
					size_t i = 0, unsent_i = state->unsent_i;
					uint64_t lo0 = state->send_seq_lo; uint32_t hi = state->send_seq_hi;
					uint64_t lo1 = lo0 - wsz/sizeof(struct _send_packet*);
					if(lo1>lo0) hi--;
					while(ring_iterator_next(&it, &p, sizeof(p), true)){
						if(!p){
							array_buffer_push_memset(&b.buf, 0, 4);
							continue;
						}
						unsigned sz = lenof(p);
						if(i < unsent_i){
							p = p->next;
							chacha_in[12] = 0;
							size_t lseq = lseqof(p);
							chacha_in[13] = (uint32_t)lseq;
#if SIZE_MAX == UINT64_MAX
							chacha_in[14] = (uint32_t)(lseq>>32);
							chacha_in[15] = hi + (uint32_t)(lseq < lo1);
#else
							uint64_t hi1 = (uint64_t)hi<<32|(uint64_t)lo1>>32 + (uint32_t)(lseq < (size_t)lo1);
							chacha_in[14] = (uint32_t)(hi1>>32); chacha_in[15] = (uint32_t)hi1;
#endif
							ChaCha20_block_xor(chacha_in, p->payload+(sz&60), sz>>6);
						}
						sz -= 16;
						uint8_t* p2 = array_buffer_push_garbage(&b.buf, sz+4);
						_write32(p2, sz | (uint32_t)(p->first<<16)); // Upper 15 bits reserved
						memcpy(p2+4, p->payload+16, sz);
						i += sizeof(p);
					}
				}
			}
			_hivemind_remote_cleanup_recv(state);
			_hivemind_remote_cleanup_send(state);
			state->handle = X_SOCKET_INVALID;
			struct _hivemind_remote* n = state->next;
			if(!state->undrained_next && !state->unsent_ack_next){
				free(state);
			}else{
				_time_lock_rel(&state->send_last_used, sl);
				_time_lock_rel(&state->recv_last_used, rl);
			}
			state = n;
		}
	}
	if(s->buckets_exp >= 2) free(s->remote_buckets);
	s->remote_buckets = 0; s->remote_count = 0;
	s->buckets_exp = 0;

	if(save){
		uint32_t mkey[8];
		for(unsigned i = 0; i < 8; i++) mkey[i] = htole32(s->master_key[i]);
		uint8_t* buf8 = (uint8_t*)array_buffer_data(&b.buf);
		Poly1305(buf8+16, array_buffer_size(&b.buf)-16, (uint8_t*)mkey, buf8);
		x_file_t f = x_open(save);
		if(f == X_FILE_INVALID) goto end;
		if(x_setsize(f, 0))
			x_write(f, 0, (uint8_t*)array_buffer_data(&b.buf), array_buffer_size(&b.buf));
		x_close(f);
	}
	end:
	array_buffer_destroy(&b.buf);
}

uint8_t* hivemind_request_buffer(size_t sz){
	if(!tls.buf_being_built) return 0;
	size_t sz0 = tls.buf_being_built->sz0;
	if(sz > sz0) array_buffer_push_garbage(&tls.buf_being_built->buf, sz - sz0);
	else if(sz < sz0) array_buffer_pop_discard(&tls.buf_being_built->buf, sz0 - sz);
	return (uint8_t*)array_buffer_data(&tls.buf_being_built->buf) + sz0;
}