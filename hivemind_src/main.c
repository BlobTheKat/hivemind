#define CHACHA20_POLY1305_IMPL
#include "tasks.c"

typedef void (*hivemind_generic_fn_t)(void*);
typedef void (*hivemind_on_msg_fn_t)(void*, const uint8_t*, size_t, void*);
typedef void* (*hivemind_pipe_restore_fn_t)(void*, uint8_t*, size_t);
typedef void (*hivemind_pipe_finish_fn_t)(void*, void*);

void hivemind_init(hivemind_server_t* s, const uint8_t master_key[32], hivemind_on_msg_fn_t on_msg){
	memset(s, 0, sizeof(*s));
	s->on_msg = on_msg;
	s->udata = s;
	s->state_lifetime = 21600000000;
	shared_lock_init(&s->state_lock);
	shared_lock_init(&s->pipes_lock);
	x_randombytes(s->_rand_bytes, 16);
#ifndef __SIZEOF_INT128__
	atomic_init(&s->_id_lock, ATOMIC_FLAG_INIT);
#endif
	for(unsigned i = 0; i < 8; i++) s->master_key[i] = (uint32_t)master_key[i<<2]|(uint32_t)master_key[i<<2|1]<<8|(uint32_t)master_key[i<<2|2]<<16|(uint32_t)master_key[i<<2|3]<<24;
}
bool hivemind_start(hivemind_server_t* s, remote_t where, ip_addr_t reflect_test, const char* from, hivemind_pipe_restore_fn_t pipe_restore){
	x_socket_t sock = x_udp_bound(where);
	if(sock == X_SOCKET_INVALID) return false;
	s->handle = sock;
	bool has_addr = s->addr.dwords[0] || s->addr.dwords[1] || s->addr.dwords[2] || s->addr.dwords[3];
	if(!has_addr || !s->port_le || !s->mtu_le){
		if(!x_udp_reflect(sock, reflect_test, &where)) err: {
			x_socket_free(sock);
			return false;
		}
		if(!has_addr) s->addr = where.addr;
		if(!s->port_le) s->port_le = htole16(where.port);
		if(!s->mtu_le) s->mtu_le = htole16(where.mtu);
	}
	// 64MB total. Can queue 32MB every SEND_TICK which is 16GB/s or 128Gbps (realistically a bit less but this is still more than good enough)
	if(!x_udp_opts(sock, 32768 * 1024, 32768 * 1024))
		goto err;
	
	if(from){
		x_file_t f = x_open(from);
		if(f == X_FILE_INVALID) goto restore_failed;
		x_remove(from);
		size_t sz = x_getsize(f);
		bool success = false;
		if(sz >= _HIVEMIND_SAVE_HEADER_SZ){
			uint8_t* data = (uint8_t*) malloc(sz);
			if(x_read(f, 0, data, sz) == sz)
				success = _hivemind_load(s, data, sz, pipe_restore);
			free(data);
		}
		x_close(f);
		if(!success) goto restore_failed;
	}else restore_failed: _nalloc_id(s, s->first_id);
	
	lock_acquire(&_hivemind_meta.threads_lock, 1);
	if(!_hivemind_meta.threads_max){
		if(!x_event_queue_init(&_hivemind_meta.queue)) err2: {
			lock_release(&_hivemind_meta.threads_lock, 1);
			goto err;
		}
		if(!x_event_queue_add(&_hivemind_meta.queue, sock, (union x_userdata_t){.ptr = s})){
			x_event_queue_destroy(&_hivemind_meta.queue);
			goto err2;
		}
		_hivemind_meta.threads_cur = 1; _hivemind_meta.threads_max = (uint32_t)available_concurrency();
		thread_detach(thread_create(_hivemind_listen, 0, 0));
	}else if(!x_event_queue_add(&_hivemind_meta.queue, sock, (union x_userdata_t){.ptr = s})) goto err2;
	hivemind_server_t* prev = atomic_load_explicit(&_hivemind_meta.servers, memory_order_relaxed);
	if(prev) prev->prevp = &s->next;
	atomic_init(&s->next, prev);
	atomic_store_explicit(s->prevp = &_hivemind_meta.servers, s, memory_order_release);
	lock_release(&_hivemind_meta.threads_lock, 1);
	return true;
}

uint8_t* hivemind_packet_detach(const uint8_t* p){
	if(tls.packet_on_heap >= SIZE_MAX-1){ tls.packet_on_heap |= 1; return (uint8_t*)p; }
	uint8_t* p2 = (uint8_t*) _hivemind_alloc(tls.packet_on_heap);
	if(tls.packet_on_heap) memcpy(p2, p, tls.packet_on_heap);
	tls.packet_on_heap = SIZE_MAX;
	return p2;
}
void hivemind_packet_free(const uint8_t* p){
	// addr&7 == 2 => offset 26 (packet with pipe and long length)
	// addr&7 == 4 => offset 20 (packet with pipe but no length, i.e length was known before allocation)
	// addr&7 == 4 => offset 20 (see zero-copy ring buffer queue, offset for that special case is 20)
	// addr&7 == 6 => offset 22 (packet with pipe and short length)
	// addr&7 == 0 => offset 0 (packet with no pipe or length)
	// addr == 0 => offset 0 (free(0) is a NOP)
	// Technically pointer arithmetic on null is UB in C (even if not dereferenced). This is why we have the weird off ? p-off : p instead of just p-off. Under -O1 or higher, this check goes away anyway, but at least we avoid nasal demons.
	unsigned off = 0b10111010110100000>>(((uintptr_t)p)<<1&12)&30;
	free((void*)(off ? p-off : p));
}
void hivemind_pipe_unlock(){
	if(tls.pipe_lock) lock_release(tls.pipe_lock, 1), tls.pipe_lock = 0;
}

void hivemind_create_pipe(hivemind_server_t* s, hivemind_pipe_t* pipe, void* udata){
	pipe->addr = s->addr; pipe->port_mtu_packed_le = s->port_mtu_packed_le;
	_alloc_id(s, pipe->id, epoch_now()/MILLISECOND_US);
	_append_pipe(s, pipe->id, udata);
}
void* hivemind_close_pipe(hivemind_server_t* s, const hivemind_pipe_t* pipe){
	if(memcmp(pipe->dwords, &s->dwords, 20)) return 0;
	return _kill_pipe(s, pipe->id);
}

void hivemind_send(hivemind_server_t* s, const hivemind_pipe_t* to, const uint8_t* msg, size_t len){
#if !defined(HIVEMIND_NO_NETWORK_BYPASS) && !defined(HIVEMIND_NO_LOCAL_BYPASS)
	if(!memcmp(s->dwords, to->dwords, 18 /* Everything except MTU */)){
		// Zero-copy loopback shortcut
		tls.packet_on_heap = len;
		_fire_pipe(s, to->id, msg, len);
		return;
	}
#endif
#if (SIZE_MAX>>1) < 0x7FFFFFFFFFFF-64
	if unlikely(len > (SIZE_MAX>>1)){
		fputs("hivemind_send(): Message size exhausts user address space", stderr);
		abort();
	}
#else
	if unlikely(len > 0x7FFFFFFFFFFF){
		fputs("hivemind_send(): Message size exhausts protocol limit", stderr);
		abort();
	}
#endif
	unsigned port = le16toh(to->port_le), mtu = le16toh(to->mtu_le);
	size_t pad_len = (len + (len > 32767 ? 89 : 85)) & -64ull, num_packets = 1;
	struct _hivemind_remote* state = _hivemind_state_find(s, to->addr, (uint16_t)port, true);
	if(state->server_mtu < mtu) mtu = state->server_mtu;
	unsigned omtu = mtu -= 20; mtu &= -64u;
	assert(mtu && mtu < 65536);
	if(pad_len > (size_t)mtu) num_packets += (pad_len-1) / mtu;
	retry: {}
	uint64_t l = _time_lock_acq(&state->send_last_used);
	if(state->send_unlocked_ref&0x80000000){
		// Someone's waiting on a strong exclusive lock
		_time_lock_rel(&state->send_last_used, l);
		thread_sleep(1); // Very strong yield
		goto retry;
	}
	shared_lock_release(&s->state_lock);
	uint64_t tim = _hivemind_internal_clock();
	state->send_unlocked_ref++;
	struct _send_packet* packet = 0; unsigned plen = 0;
	uint64_t seq_lo;
	/*critical*/ {
		if unlikely(l == 1 || (tim-l) > s->state_lifetime){
			if unlikely(ring_buffer_size(&state->send_queue)) _hivemind_remote_cleanup_send(state);
			num_packets += (omtu-mtu)<16 && (num_packets*mtu-pad_len) < 64;
			omtu = (omtu-16)&-64u;
			plen = pad_len > (size_t)omtu ? omtu : (unsigned)pad_len;
			packet = (struct _send_packet*) _hivemind_alloc(sizeof(struct _send_packet) + 36 + plen);
			_ram_packed_kex(s, to->id, state, (uint32_t*)(packet->payload+16));
			state->send_seq_hi = state->send_seq_lo = 0;
		}
		seq_lo = state->send_seq_lo;
		if((state->send_seq_lo = seq_lo+num_packets) < seq_lo) state->send_seq_hi++;
		if(state->unsent_i == ring_buffer_size(&state->send_queue)){
			state->rtt_gate_hi = 0;
			state->rtt_gate_lo = 8;
		}
		ring_buffer_push_memset(&state->send_queue, 0, num_packets*sizeof(struct _send_packet*), false);
	}
	_time_lock_rel(&state->send_last_used, tim);
	struct _send_packet** packets = (struct _send_packet**)(num_packets <= 8 ? alloca(num_packets*sizeof(struct _send_packet*)) : _hivemind_alloc(num_packets*sizeof(struct _send_packet*))), **ppackets = packets;
	unsigned header = 20;
	if likely(!plen){
		plen = (pad_len > (size_t)mtu) ? mtu : (unsigned)pad_len;
		packet = (struct _send_packet*) _hivemind_alloc(sizeof(struct _send_packet) + 20 + plen);
		*(uint32_t*)(packet->payload+16) = htole32(seq_lo);
		memcpy(packet->payload+20, to->id, 20);
	}else header = 36;
	uint8_t* p = packet->payload + header;
	unsigned j = 20;
	if(len < 32768){
		*(uint16_t*)(p+j) = htole16(len<<1);
		j += 2;
	}else{
		*(uint32_t*)(p+j) = htole32((len-1)<<1|1);
		*(uint16_t*)(p+j+4) = htole16((len-1)>>31);
		j += 6;
	}
	if(pad_len <= plen){
		// last packet
		memset(p + j + len, 0, plen - j - len);
		if(len) memcpy(p + j, msg, len);
	}else{
		memcpy(p + j, msg, plen-j);
		msg += plen-j; len -= plen-j;
	}
	packet->first = 1;
	packet->resent = 0;
	goto encode;
	more: {
		plen = (pad_len > (size_t)mtu) ? mtu : (unsigned)pad_len;
		packet = (struct _send_packet*) _hivemind_alloc(sizeof(struct _send_packet) + 20 + plen);
		packet->first = packet->resent = 0;
		header = 20; p = packet->payload+20;
		*(uint32_t*)(packet->payload+16) = htole32(seq_lo);
		if(pad_len <= plen){
			// last packet
			memset(p + len, 0, plen - len);
			if(len) memcpy(p, msg, len);
		}else{
			memcpy(p, msg, plen);
			msg += plen; len -= plen;
		}
	}
	encode:
	pad_len -= plen;
	packet->len_p = (plen+header) >> 5;
#if SIZE_MAX == UINT64_MAX
	packet->seq_m = seq_lo>>32;
#endif
	seq_lo++;
	*ppackets++ = packet;
	if(pad_len) goto more;
	assert((size_t)(ppackets - packets) == num_packets);

	_time_lock_acq(&state->send_last_used);
	state->send_unlocked_ref--;
	size_t i = ring_buffer_size(&state->send_queue) + (seq_lo - state->send_seq_lo - num_packets) * sizeof(struct _send_packet*);
	ring_buffer_set(&state->send_queue, i, packets, sizeof(struct _send_packet*) * num_packets, false);
	_drain_writes(state, tim = _hivemind_internal_clock());
	if(!state->undrained_next){
		struct _hivemind_remote* n = atomic_load_explicit(&_hivemind_meta.undrained, memory_order_relaxed);
		retry_acq: state->undrained_next = n;
		if(!atomic_compare_exchange_weak_explicit(&_hivemind_meta.undrained, &n, state, memory_order_acq_rel, memory_order_relaxed)) goto retry_acq;
		x_event_queue_wake(&_hivemind_meta.queue, SEND_TICK);
	}
	_time_lock_rel(&state->send_last_used, tim);

	if(num_packets>8) free(packets);
}

void hivemind_quit(hivemind_server_t* s, hivemind_generic_fn_t on_close, const char* to, hivemind_pipe_finish_fn_t pipe_finish){
	size_t to_len = to ? strlen(to)+1 : 1;
	struct _open_close_data* oc = malloc(sizeof(struct _open_close_data) + to_len);
	oc->cb = on_close;
	oc->finish_cb = pipe_finish;
	if(to_len>1) memcpy(oc->filename, to, to_len+1);
	else oc->filename[0] = '\0';
	s->oc = oc;
	x_socket_t h = s->handle;
	tsan_fence(memory_order_release);
	x_udp_close(h);
}

static const char b64_alphabet[64] = {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5','6','7','8','9','-','_'};
// Parsing chars >= 128 as whatever they map to mod 128 is smelly but very slightly faster and non-base64 chars should not appear in pipe strings anyway (especially when the rest of the pipe is correct), if they do it's on you.
static const uint8_t b64_alphabet2[128] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,62,0,62,0,63,52,53,54,55,56,57,58,59,60,61,0,0,0,0,0,0,0,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,0,0,0,0,63,0,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,0,0,0,0,0};
size_t hivemind_pipe_to_string(const hivemind_pipe_t* pipe, char out[HIVEMIND_PIPE_STR_MAX_LEN]){
	ip_to_string(pipe->addr, out);
	size_t i = strlen(out);
	snprintf(out+i, HIVEMIND_PIPE_STR_MAX_LEN-i, "/%u/%u/%llu/", le16toh(pipe->port_le), le16toh(pipe->mtu_le), (unsigned long long)le32toh(pipe->id[0])<<32|((unsigned long long)le32toh(pipe->id[1])&0xFFFFFF));
	i += strlen(out+i+7)+7;
	uint8_t* rand = (uint8_t*)pipe->id + 7;
	for(int j = 0; j < 4; j++){
		uint32_t x = (uint32_t)(rand[j*3]<<16|rand[j*3+1]<<8|rand[j*3+2]);
		out[i++] = b64_alphabet[x>>18]; out[i++] = b64_alphabet[x>>12&63];
		out[i++] = b64_alphabet[x>>6&63]; out[i++] = b64_alphabet[x&63];
	}
	out[i++] = b64_alphabet[rand[12]>>2]; out[i++] = b64_alphabet[(rand[12]<<4)&63];
	out[i] = 0;
	return i;
}
bool hivemind_pipe_from_string(hivemind_pipe_t* pipe, const char in[HIVEMIND_PIPE_STR_MAX_LEN]){
	size_t len = strnlen(in, HIVEMIND_PIPE_STR_MAX_LEN);
	if(len >= HIVEMIND_PIPE_STR_MAX_LEN) return false;
	char str[HIVEMIND_PIPE_STR_MAX_LEN];
	memcpy(str, in, len+1);
	char* f = strchr(str, '/');
	if(!f) return false;
	size_t i = (size_t)(f-str);
	if(i >= len) return false;
	str[i] = '\0';
	pipe->addr = ip_from_string(str);
	unsigned port, mtu, off; unsigned long long tim;
	char id_b64[19];
	if(sscanf(str+i+1, "%u/%u/%llu/%18s%n", &port, &mtu, &tim, id_b64, &off) != 4) return false;
	if((off+i+1) != len) return false;
	pipe->port_le = htole16(port); pipe->mtu_le = htole16(mtu);
	for(int i = 0; i < 4; i++){
		uint32_t x = (uint32_t)(b64_alphabet2[id_b64[i<<2]&127]<<18|b64_alphabet2[id_b64[i<<2|1]&127]<<12|b64_alphabet2[id_b64[i<<2|2]&127]<<6|b64_alphabet2[id_b64[i<<2|3]&127]);
		str[i*3+3] = (char)(x>>16); str[i*3+4] = (char)(x>>8); str[i*3+5] = (char)x;
	}
	str[15] = (char)(b64_alphabet2[id_b64[16]&127]<<2|b64_alphabet2[id_b64[17]&127]>>4);
	memcpy(pipe->id+2, str+4, 12); // byte str+3 is copied manually
	pipe->id[0] = htole32(tim>>24);
	pipe->id[1] = htole32(tim&0xFFFFFF|(uint32_t)str[3]<<24);
	return true;
}