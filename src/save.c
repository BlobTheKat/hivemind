#define _HV_SAVE_HEADER_SZ 96
#include "tasks.c"

static inline uint64_t _hv_read64(const uint8_t* p){
	return (uint64_t)p[0]<<56|(uint64_t)p[1]<<48|(uint64_t)p[2]<<40|(uint64_t)p[3]<<32|(uint64_t)p[4]<<24|(uint64_t)p[5]<<16|(uint64_t)p[6]<<8|(uint64_t)p[7];
}
static inline void _hv_write64(uint8_t* p, uint64_t x){
	p[0] = (uint8_t)(x>>56); p[1] = (uint8_t)(x>>48); p[2] = (uint8_t)(x>>40); p[3] = (uint8_t)(x>>32);
	p[4] = (uint8_t)(x>>24); p[5] = (uint8_t)(x>>16); p[6] = (uint8_t)(x>>8); p[7] = (uint8_t)x;
}
static inline uint64_t _hv_read48(const uint8_t* p){
	return (uint64_t)p[0]<<40|(uint64_t)p[1]<<32|(uint64_t)p[2]<<24|(uint64_t)p[3]<<16|(uint64_t)p[4]<<8|(uint64_t)p[5];
}
static inline void _hv_write48(uint8_t* p, uint64_t x){
	p[0] = (uint8_t)(x>>40); p[1] = (uint8_t)(x>>32); p[2] = (uint8_t)(x>>24);
	p[3] = (uint8_t)(x>>16); p[4] = (uint8_t)(x>>8); p[5] = (uint8_t)x;
}
static inline uint32_t _hv_read32(const uint8_t* p){
	return (uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|(uint32_t)p[3];
}
static inline void _hv_write32(uint8_t* p, uint32_t x){
	p[0] = (uint8_t)(x>>24); p[1] = (uint8_t)(x>>16); p[2] = (uint8_t)(x>>8); p[3] = (uint8_t)x;
}

static inline bool _hv_load(hivemind_server_t* s, uint8_t* data, size_t sz, hivemind_pipe_restore_fn_t pipe_restore){
	// Poly1305 checksum. By using the master key as the poly tag, we can verify the master key hasn't changed,
	//   without storing it or a hash of it in the file. Very cool
	uint32_t tag[4], mkey[8];
	for(unsigned i = 0; i < 8; i++) mkey[i] = htole32(s->master_key[i]);
	Poly1305(data+16, sz-16, (uint8_t*)mkey, (uint8_t*)tag);
	if(memcmp16(tag, data)) return false;

	// Reserved
	if(_hv_read32(data+16)) return false;

	uint64_t pipec = _hv_read64(data+20), remc = _hv_read64(data+28);

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

	uint8_t* p = data+_HV_SAVE_HEADER_SZ, *end = data + sz;

	while(pipec--){
		// Let's not complicate things, this is good enough
		if(p+28 > end) break;
		uint64_t sz = _hv_read64(p+20);
		uint8_t* p2 = p+28+((sz+3ull)&~3ull);
		if(p2 > end) break;
		_hv_append_pipe(s, (uint32_t*)p, pipe_restore(s->udata, p+28, sz));
		p = p2;
	}

	while(remc--){
		if(p+20 > end) break;
		ip_addr_t addr; memcpy(addr.bytes, p, 16);
		uint32_t x = _hv_read32(p+16);
		struct _hv_remote* state = _hv_state_find(s, addr, (uint16_t)x, _HV_FIND_CREATE);
		bool bypass = state->bypass_type & 1;
		p += 20;
		bool r = x>>16&1, w = x>>17&1;
		uint8_t* pw = p+64;
		if(!state){
			if(r){
				if(p+64 > end) break;
				size_t rsz = _hv_read64(p+52);
				p += 64 + w*68;
				for(; rsz; rsz--){
					unsigned sz = _hv_read32(p);
					if((sz-1) < 0xFFFE){ // !(sz>>16) && sz!=0 && sz != 0xFFFF
						p += 8+sz;
					}else if(sz > 0x3ffff){
						p += 44+_hv_read48(p+10);
					}else p += sz > 0x1ffff ? 8 : 4;
				}
			}
			if(w){
				if(pw+68 > end) break;
				size_t wsz = _hv_read64(pw+52);
				for(; wsz; wsz--)
					p += _hv_read32(p)+4;
			}
			continue;
		}
		if(r){
			if(p+64 > end || atomic_load_explicit(&state->recv_last_used, memory_order_relaxed) > 1) break;
			for(unsigned i = 0; i < 8; i++) state->recv_key[i] = _hv_read32(p+i*4);
			uint64_t rl = _hv_read64(p+32);
			if(rl>1) atomic_store_explicit(&state->recv_last_used, rl, memory_order_relaxed);
			state->recv_seq_hi = _hv_read32(p+40);
			state->recv_seq_lo = _hv_read64(p+44);
			size_t rsz = _hv_read64(p+52);
			state->key_derived_when = _hv_read64(p+60);
			p += 64 + w*68;
			for(; rsz; rsz--){
				unsigned sz = _hv_read32(p);
				sfat_pointer_t p0;
				if((sz-1) < 0xFFFE){ // !(sz>>16) && sz!=0 && sz != 0xFFFF
					uint8_t* p2 = malloc(sz + (bypass?12:20)) + (bypass?12:20);
					*(uint32_t*)(p2-4) = _hv_read32(p+4);
					memcpy(p2, p+8, sz);
					p += 8+sz;
					p0 = sfat_pack(p2, sz);
				}else if(sz > 0x3ffff){
					// block
					size_t cur = _hv_read48(p+10);
					struct _hv_packet_reassembly* block = malloc(sizeof(struct _hv_packet_reassembly) + cur);
					block->cur = cur;
					block->total = _hv_read48(p+4);
					block->pipe_last = _hv_read48(p+16);
					block->pipe_next = _hv_read48(p+20);
					memcpy(block->pipe, p+24, 20);
					memcpy(block->data, p+44, cur);
					p += 44+cur;
					p0 = sfat_pack(block, sz&0x10000 ? 0xFFFF : 0);
				}else if(sz > 0x1ffff){
					// dep
					p0 = sfat_pack(_hv_read32(p+4), 0xFFFE);
					p += 8;
				}else{
					p0 = sfat_pack(0, sz&0x10000 ? 0xFFFF : 0);
					p += 4;
				}
				ring_buffer_push(&state->recv_queue, &p0, sizeof(p0), true);
			}
		}
		next:
		if(w){
			if(pw+68 > end || atomic_load_explicit(&state->send_last_used, memory_order_relaxed) > 1) break;
			for(unsigned i = 0; i < 8; i++) state->send_key[i] = _hv_read32(pw+i*4);
			uint64_t sl = _hv_read64(pw+32);
			if(sl) atomic_store_explicit(&state->send_last_used, sl, memory_order_relaxed);
			state->send_seq_hi = _hv_read32(pw+40);
			state->send_seq_lo = _hv_read64(pw+44);
			size_t wsz = _hv_read64(pw+52);
			uint32_t tmp = _hv_read32(pw+60);
			memcpy(&state->avg_latency, &tmp, sizeof(tmp));
			tmp = _hv_read32(pw+64);
			memcpy(&state->us_per_byte, &tmp, sizeof(tmp));
			state->growth = -1.f;

			size_t lo0 = state->send_seq_lo - wsz;
			for(; wsz; wsz--){
				unsigned sz = _hv_read32(p);
				struct _hv_send_packet* p2 = 0;
				if(sz){
					bool asz = sz + (bypass?8:16);
					p2 = malloc(sizeof(struct _hv_send_packet) + asz);
					p2->first = sz>>16; p2->kex = sz>>17; p2->resent = 0; p2->len4 = asz>>2;
					if(p2->first && bypass)
						p2->len4--;
					memcpy(p2->payload4+(bypass?2:4), p+4, sz);
				}
				p += 4+sz;
				lo0++;
				ring_buffer_push(&state->send_queue, &p2, sizeof(struct _hv_send_packet*), true);
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

static inline void _hv_finish(hivemind_server_t* s, void (*pipe_finish)(void*,void*), const char* save){
	struct _hv_tls_buf_being_built b;
	size_t pipe_top = atomic_load_explicit(&s->pipes_heap_i, memory_order_relaxed);
	size_t pipec = pipe_top - atomic_load_explicit(&s->deleted_pipes, memory_order_relaxed);
	if(save){
		uint8_t* header = array_buffer_push_garbage(&b.buf, _HV_SAVE_HEADER_SZ);

		_hv_write32(header+16, 0); // Reserved
		_hv_write64(header+20, pipec); _hv_write64(header+28, s->remote_count);

		memcpy(header+36, s->dwords, 20); // addr/port/mtu
		memcpy(header+56, s->first_id, 20);
		_hv_nalloc_id(s, (uint32_t*)(header+76));
	}

	struct _hv_pipe* pheap = (struct _hv_pipe*)(s->pipes_data + ((1ull<<s->pipes_bucket_exp)&-2ull));
	tls.buf_being_built = save ? &b : 0;
	for(size_t i = 0; i < pipe_top; i++){
		struct _hv_pipe* p = pheap+i;
		if(atomic_load_explicit(&p->next, memory_order_relaxed)&1ull){
			// deleted
			pipec++;
			continue;
		}
		if(save){
			b.sz0 = array_buffer_size(&b.buf)+28;
			pipe_finish(s->udata, p->udata);
			size_t sz = array_buffer_size(&b.buf);
			if(sz >= b.sz0){
				sz -= b.sz0;
				uint8_t* data = (uint8_t*)array_buffer_data(&b.buf) + b.sz0-28;
				memcpy(data, p->id, 20);
				_hv_write64(data+20, sz);
				if(sz&3) array_buffer_push_garbage(&b.buf, ~sz&3);
			}
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
	struct _hv_remote** r = s->remote_buckets;
	if(buckets < 2) r = (struct _hv_remote**) &s->remote_buckets;
	uint64_t t = _hv_internal_clock(), life = s->state_lifetime;
	for(size_t i = 0; i < buckets; i++){
		struct _hv_remote* state = r[i];
		while(state){
			if(state->bypass_type & 2){
				struct _hv_remote_vq* state_vq = (struct _hv_remote_vq*)state;
				vqueue_close(&state_vq->q);
				assert(!state_vq->ref);
				struct _hv_remote* n = state->next;
				free(state);
				state = n;
				continue;
			}
			uint64_t rl = _hv_time_lock_acq(&state->recv_last_used);
			uint64_t sl = _hv_time_lock_acq(&state->send_last_used);
			assert(!state->recv_unlocked_ref && !state->send_unlocked_ref);
			state->ack_coal_i = 0;
			bool bypass = state->bypass_type == 1;
			if(save){
				// Save: { Send, Recv } { Buffer, Seq, Last used } + Read KDW + Write RQR state
				bool r = rl!=1&&(t>life+life?rl>=t-life-life:true), w = sl!=1&&(t>life?sl>=t-life:true);
				uint8_t* head = array_buffer_push_garbage(&b.buf, r*64+w*68+20);
				memcpy(head, state->addr.bytes, 16);
				_hv_write32(head+16, (uint32_t)(state->port|w<<16|r<<17)); head += 20; // Upper 14 bits reserved
				size_t rsz = state->recv_queue.size, wsz = state->send_queue.size;
				if(r){
					for(unsigned i = 0; i < 8; i++) _hv_write32(head+i*4, state->recv_key[i]);
					_hv_write64(head+32, rl);
					_hv_write32(head+40, state->recv_seq_hi);
					_hv_write64(head+44, state->recv_seq_lo);
					_hv_write32(head+52, rsz / sizeof(sfat_pointer_t));
					_hv_write64(head+56, state->key_derived_when);
					head += 64;
				}
				if(w){
					for(unsigned i = 0; i < 8; i++) _hv_write32(head+i*4, state->send_key[i]);
					_hv_write64(head+32, sl);
					_hv_write32(head+40, state->send_seq_hi);
					_hv_write64(head+44, state->send_seq_lo);
					_hv_write64(head+52, wsz / sizeof(struct _hv_send_packet*));
					uint32_t tmp; memcpy(&tmp, &state->avg_latency, sizeof(tmp));
					_hv_write32(head+60, tmp);
					memcpy(&tmp, &state->us_per_byte, sizeof(tmp));
					_hv_write32(head+64, tmp);
				}
				if(r){
					ring_iterator_t it = ring_buffer_iterator(&state->recv_queue, 0, -1ull);
					assert(it.remaining == rsz);
					sfat_pointer_t p;
					while(ring_iterator_next(&it, &p, sizeof(p), true)){
						unsigned sz = sfat_size(p);
						uint8_t* data = sfat_get(p);
						uint8_t* buf2;
						if(!sz){
							if(data){
								buf2 = array_buffer_push_garbage(&b.buf, 44 + ((struct _hv_packet_reassembly*)data)->cur);
								_hv_write32(buf2, 0x40000);
								write_block: {}
								struct _hv_packet_reassembly* block = (struct _hv_packet_reassembly*)data;
								_hv_write48(buf2+4, block->total);
								_hv_write48(buf2+10, block->cur);
								_hv_write32(buf2+16, block->pipe_last);
								_hv_write32(buf2+20, block->pipe_next);
								memcpy(buf2+24, block->pipe, 20);
								memcpy(buf2+44, block->data, block->cur);
							}else array_buffer_push_memset(&b.buf, 0, 4);
						}else if(sz == 0xFFFE){
							buf2 = array_buffer_push_garbage(&b.buf, 8);
							_hv_write32(buf2, 0x20000);
							_hv_write32(buf2+4, (uint32_t)(uintptr_t)data);
						}else if(sz == 0xFFFF){
							if(data){
								buf2 = array_buffer_push_garbage(&b.buf, 20 + ((struct _hv_packet_reassembly*)data)->cur);
								_hv_write32(buf2, 0x50000);
								goto write_block;
							}else _hv_write32(array_buffer_push_garbage(&b.buf, 4), 0x10000);
						}else{
							buf2 = array_buffer_push_garbage(&b.buf, sz+8);
							_hv_write32(buf2, sz); // Upper 16 bits zero
							_hv_write32(buf2+4, *(uint32_t*)(data-4));
							memcpy(buf2+8, data, sz);
						}
					}
				}
				if(w){
					uint32_t chacha_in[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}; // "expand 32-byte k"
					memcpy(chacha_in+4, state->send_key, 32);
					ring_iterator_t it = ring_buffer_iterator(&state->send_queue, 0, -1ull);
					assert(it.remaining == wsz);
					struct _hv_send_packet* p;
					size_t i = 0;
					uint64_t lo0 = state->send_seq_lo; uint32_t hi = state->send_seq_hi;
					uint64_t lo1 = lo0 - wsz/sizeof(struct _hv_send_packet*);
					if(lo1>lo0) hi--;
					while(ring_iterator_next(&it, &p, sizeof(struct _hv_send_packet*), true)){
						if(!p){
							array_buffer_push_memset(&b.buf, 0, 4);
							continue;
						}
						unsigned sz = (p->len4<<2) - (bypass ? 8 : 16);
						if(bypass && p->first) sz += 4;
						p = p->next;
						if(!bypass) _hv_unencrypt_packet(chacha_in, hi, lo1, p);
						uint8_t* p2 = array_buffer_push_garbage(&b.buf, sz+4);
						_hv_write32(p2, sz | (uint32_t)(p->first<<16) | (uint32_t)(p->kex<<17)); // Upper 14 bits reserved
						memcpy(p2+4, p->payload4+(bypass?2:4), sz);
						i += sizeof(struct _hv_send_packet*);
					}
				}
			}
			_hv_remote_cleanup_recv(state, bypass);
			_hv_remote_cleanup_send(state);
			// Signal to undrained/unsent_ack that this state is no longer needed and should be freed once done
			state->prevp = 0;
			struct _hv_remote* n = state->next;
			if(!state->undrained_next && !state->unsent_ack_next){
				free(state);
			}else{
				_hv_time_lock_rel(&state->send_last_used, 1);
				_hv_time_lock_rel(&state->recv_last_used, 1);
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
		x_file_t f = x_open(save, X_FILE_SEQUENTIAL);
		if(f == X_FILE_INVALID) goto end;
		if(x_setsize(f, 0))
			x_write(f, (uint8_t*)array_buffer_data(&b.buf), 0, array_buffer_size(&b.buf));
		x_close(f);
	}
	end:
	array_buffer_destroy(&b.buf);
}

uint8_t* hivemind_request_buffer(size_t sz){
	if(!tls.buf_being_built) return 0;
	size_t sz0 = tls.buf_being_built->sz0;
	array_buffer_setsize_garbage(&tls.buf_being_built->buf, sz0 + sz);
	return (uint8_t*)array_buffer_data(&tls.buf_being_built->buf) + sz0;
}