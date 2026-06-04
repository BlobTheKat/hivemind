#pragma once
#if defined(__APPLE__) && !defined(__STDC_WANT_LIB_EXT1__)
	#define __STDC_WANT_LIB_EXT1__ 1
#endif
#include "a.h"
#include "chacha20poly1305.h"
#include "x.h"
#include <time.h>
#include <stdatomic.h>
#include <alloca.h>
#include "utils.h"

static_assert(CHAR_BIT == 8);

#define _hivemind_internal_clock() mono_now()

#define memcmp16(a, b) (((uint64_t)(a)[0]|(uint64_t)(a)[1]<<32) ^ ((uint64_t)(b)[0]|(uint64_t)(b)[1]<<32)) | \
	(((uint64_t)(a)[2]|(uint64_t)(a)[3]<<32) ^ ((uint64_t)(b)[2]|(uint64_t)(b)[3]<<32))

static inline void* _hivemind_alloc(size_t bytes){
	void* addr = malloc(bytes);
	if unlikely(!addr){
		fputs("_hivemind_alloc(): Heap out of memory", stderr);
		abort();
	}
	assert(!((uintptr_t)addr&7)); // Aligned
	return addr;
}
static inline void* _hivemind_alloc_a(size_t bytes, size_t to){
	void* addr = aligned_alloc(to, bytes);
	if unlikely(!addr){
		fputs("_hivemind_alloc(): Heap out of memory", stderr);
		abort();
	}
	return addr;
}

// Used by hashmaps
static inline uint64_t _mix64(uint64_t x){
	x ^= x >> 30;
	x *= 0xbf58476d1ce4e5b9ULL;
	x ^= x >> 27;
	x *= 0x94d049bb133111ebULL;
	x ^= x >> 31;
	return x;
}

struct _send_packet{
	struct _send_packet* next;
#if SIZE_MAX == UINT64_MAX
	uint32_t seq_m;
#endif
	uint64_t len_p:11, resent:4, first:1, time_lo:48;
	alignas(4) uint8_t payload[];
};

static inline size_t lseqof(struct _send_packet* p){
	if(p->len_p&1) return 0;
	size_t seq = (size_t)le32toh(*(uint32_t*)(p->payload+16));
#if SIZE_MAX >= UINT64_MAX
	seq |= (size_t)p->seq_m<<32;
#endif
	return seq;
}

static inline unsigned lenof(struct _send_packet* p){
	return (unsigned)(p->len_p<<5) | (p->len_p&1 ? 4u : 20u);
}

#ifdef __SIZEOF_INT128__
typedef signed __int128 int128_t;
typedef unsigned __int128 uint128_t;
#endif

struct _hivemind_remote{
	// Field order is specific and to avoid an entire cache line of wasted padding and reduce false sharing
	// This layout is optimized for 64 bit pointers and size_t.

	// == 1st cache line: infrequently written. This line needs to be quick to access across many threads since it's what's used to traverse the linked list ==

	// Linked list structure for use in linked list hashmaps
	struct _hivemind_remote* next;
	// Used as key in hashmaps
	union{
		remote_t remote;
		struct{
			ip_addr_t addr; uint16_t port, server_mtu;
			x_socket_t handle;
		};
	};

	uint32_t send_key[8]; // Derived local key for outgoing

	// == 2nd-4th cache line: frequently written by recv logic ==

	// See send_last_used
	alignas(CACHE_LINE) atomic uint64_t recv_last_used;
	// See send_unlocked_ref
	uint32_t recv_unlocked_ref;
	uint32_t recv_seq_hi; uint64_t recv_seq_lo; // Protocol sequence numbers

	// Ring buffer of out-of-order-packets
	// cur_packet contains the currently-being-reconstructed packet, if any, and its length in cur_packet_left (if no packet is being reconstructed then cur_packet_left is undefined)
	// recv_queue[0] contains the head of the currently-being-reconstructed (head = where data is appended). This replaces what would otherwise certainly be a null (since the next packet that hasn't yet been received). If no packet is being reconstructed, then this is null (or if there are no packets in the queue then the queue is completely empty)
	ring_buffer_t recv_queue;
	uint8_t* cur_packet; size_t cur_packet_left; // see recv_queue

	// ---

	// Back pointer for `_hivemind_meta.servers` linked list
	struct _hivemind_remote** prevp;
	// Key derivation timestamp to thwart replay attacks. Forgotten after state cutoff (all key derivations older than that window are rejected regardless)
	uint64_t key_derived_when;
	// Derived local key for incoming packets (and to sign ACKs)
	uint32_t recv_key[8];

	// ACK coalescing stuff
	// Linked list of all remotes with unsent acks
	struct _hivemind_remote* unsent_ack_next;
	// ACK coalescing stuff
	// ack_coal_i = current index in ack_coal_buf
	// ack_coal_tim0 = _hivemind_internal_clock() time for first ack, used to encode `dt`s in ack_coal_buf
	uint64_t ack_coal_tim0:56, ack_coal_i:8;
	// ---

	// Buffer of coalesced acks. Up to 16 acks can be coalesced together (the 16th is stored in `_hivemind_queue_ack`'s stack when the buffer is found to be full). When the buffer is not full, the last element in this buffer is the low 32 bits of the ack's base sequence. All other values are packed `diff`s + `dt`s.
	uint32_t ack_coal_buf[15];

	// 4 bytes left

	// == 5-6th cache line: frequently written by send/drain logic ==

	// Timestamp when last packet was sent. Also used as a lock and init flag (1 = uninit, 0 = locked)
	// See _time_lock_acq/_time_lock_rel
	alignas(CACHE_LINE) atomic uint64_t send_last_used;
	// While unmasking a packet, or performing another expensive operation, it is not beneficial to unnecessarily hold on to the send_last_used lock. We temporarily release that lock, incrementing this value to make sure the remote is not GC'd in between. Since this value is only touched inside the lock, it does not need to be atomic
	uint32_t send_unlocked_ref;
	uint32_t send_seq_hi; uint64_t send_seq_lo; // Protocol sequence numbers
	// Linked list of undrained queues
	struct _hivemind_remote* undrained_next;
	// send_key is moved to the first cache line to save 1 cache line on the struct size
	// It's infrequently written so this should be fine performance-wise
	
	// (Potentially hole-y) Ring buffer of send packets.
	// `[0, unsent_i)` => Sent but unacked. These are in the send_order linked list. Each element is a pointer to &prev->next. This allows us to remove the packet from the linked list easily without making it a doubly linked list.
	// `[unsent_i, end)` => Unsent packets (direct pointers, they are not in the linked list yet)
	ring_buffer_t send_queue; size_t unsent_i;
	// ---
	// Linked list of all sent packets, in the order that they were last sent (and therefore the same order that they should be resent if needed).
	// `send_order_end` is not a pointer to the last packet but to the last packet's next field (or a pointer to `send_order_start` if the list is empty). `*send_order_end` should always be `NULL`
	struct _send_packet *send_order_start, **send_order_end;
	// Rolling window for tracking how many packets can be sent how fast
	uint64_t send_window;
	// Packed tightly for memory efficiency
	// `min_latency_when` -> When `min_latency` was achieved
	// `last_ack` -> When the last ack was received
	// rtt_gate = rtt_gate_lo|rtt_gate_hi<<16 -> Sequence number of when to start measuring latency deltas. We don't want to do this during the first RTT since that's when we're finding the min/average latency.
	// `rtt_gate == 0` -> No packets acked yet. When the first packet is acked, rtt_gate is set to the next unsent packet if any
	// `rtt_gate == seq<<1|1` -> Wait until this seq to start measuring latency deltas
	// `rtt_gate == 2` -> We are measuring latency deltas
	uint64_t min_latency_when:48, rtt_gate_lo:16; uint64_t last_ack:48, rtt_gate_hi:16;
	// Minimum latency that was captured somewhat recently
	// Average latency over some amount of RTTs
	// Microseconds per byte (inverse bandwidth), adjusted for growth rate
	// Growth rate, used to inflate `us_per_byte` to try sending faster when we thing more bandwidth may be available
	float min_latency, avg_latency, us_per_byte, growth;
	struct hivemind_server_t* server;
};

// We don't need it to be 384 exactly but we wanna know if it ever jumps up
// In that case, either reshuffle fields to keep it same size or increase this assert to the new size
// Struct alignment >= CACHE_LINE so even a single poorly placed field can bump the size dramatically
static_assert(sizeof(struct _hivemind_remote) <= 384, "sizeof(_hivemind_remote) changed");

struct _hivemind_pipe{
	atomic uintptr_t next;
	uint32_t id[5]; lock_t ref;
	void* udata;
};

struct _open_close_data{
	void (*cb)(void*);
	union{
		void* (*restore_cb)(void*, uint8_t*, size_t);
		void (*finish_cb)(void*, void*);
	};
	char filename[];
};

typedef struct hivemind_server_t hivemind_server_t;
struct hivemind_server_t{
	union{
		struct{
			ip_addr_t addr;
			union{ struct{ uint16_t port_le, mtu_le; }; uint32_t port_mtu_packed_le; };
		};
		uint32_t dwords[5];
	};
	uint8_t buckets_exp, pipes_bucket_exp;
#ifndef __SIZEOF_INT128__
	atomic_flag _id_lock;
#endif
	void* udata;
	uint64_t state_lifetime;
	uint32_t master_key[8];
#ifdef __SIZEOF_INT128__
	union{
		atomic uint128_t _id;
		char _rand_bytes[16];
	};
#else
	union{
		struct{ uint64_t _id_hi, _id_lo; };
		char _rand_bytes[16];
	};
#endif
	shared_lock_t state_lock, pipes_lock;
	size_t remote_count;
	struct _hivemind_remote** remote_buckets;
	void (*on_msg)(void*, const uint8_t*, size_t, void*);
	atomic(size_t) pipes_heap_i, deleted_pipes;
	atomic(uintptr_t)* pipes_data;
	struct _open_close_data* oc;
	atomic(hivemind_server_t*) next, *prevp;
	x_socket_t handle;
	uint32_t first_id[5];
	alignas(256) char end_[];
};

static_assert(sizeof(hivemind_server_t) == 256);

#ifdef __SIZEOF_INT128__
static void _alloc_id(hivemind_server_t* s, uint32_t out[5], uint64_t t){
	uint128_t v = atomic_fetch_add_explicit(&s->_id, 1, memory_order_relaxed);
	out[0] = htole32(t>>24); out[1] = htole32(t&0xFFFFFF|v>>96<<24);
	out[2] = htole32(v>>64); out[3] = htole32(v>>32);
	out[4] = htole32(v);
}
static void _nalloc_id(hivemind_server_t* s, uint32_t out[5]){
	uint64_t t = epoch_now()/MILLISECOND_US;
	uint128_t v = atomic_load_explicit(&s->_id, memory_order_relaxed);
	out[0] = htole32(t>>24); out[1] = htole32(t&0xFFFFFF|v>>96<<24);
	out[2] = htole32(v>>64); out[3] = htole32(v>>32);
	out[4] = htole32(v);
}
#else
#warning No 16-byte atomic primitive detected. If they are available, consider compiling with appropriate flags, e.g -mcx16. Falling back to lock-based approach
static void _alloc_id(hivemind_server_t* s, uint32_t out[5], uint64_t t){
	uint8_t spin = 32;
	while(atomic_flag_test_and_set_explicit(&s->_id_lock, memory_order_acquire)) if(spin) spin--, thread_relax(); else thread_yield();
	uint64_t lo = s->_id_lo++, hi = s->_id_hi; if(lo == -1ull) s->_id_hi = hi+1;
	atomic_flag_clear_explicit(&s->_id_lock, memory_order_release);
	out[0] = htole32(t); out[1] = htole32(t<<8>>40|hi>>32<<24);
	out[2] = htole32(hi); out[3] = htole32(lo>>32);
	out[4] = htole32(lo);
}
static void _nalloc_id(hivemind_server_t* s, uint32_t out[5]){
	uint64_t t = _hivemind_internal_clock();
	uint8_t spin = 32;
	while(atomic_flag_test_and_set_explicit(&s->_id_lock, memory_order_acquire)) if(spin) spin--, thread_relax(); else thread_yield();
	uint64_t lo = s->_id_lo, hi = s->_id_hi;
	atomic_flag_clear_explicit(&s->_id_lock, memory_order_release);
	out[0] = htole32(t); out[1] = htole32(t<<8>>40|hi>>32<<24);
	out[2] = htole32(hi); out[3] = htole32(lo>>32);
	out[4] = htole32(lo);
}
#endif

// Time-carrying lock. These locks are used both to protect a resource and signal when it was last used (for GC). States are:
// 0 = locked
// 1 = uninitialized (serves as a sentinel value for "never used before")
// >1 = unlocked and contains the time of last use. The time is updated on most lock releases (but not all, e.g if the lock was acquired but the resource wasn't "touched")
static uint64_t _time_lock_acq(atomic(uint64_t)* ptr){
	uint64_t l;
	for(;;){
		l = atomic_exchange_explicit(ptr, 0, memory_order_acquire);
		if(l) return l;
		thread_yield();
	}
}
// Peek at the value of a time lock without acquiring it. See `_time_lock_acq`
static uint64_t _time_lock_peek(atomic(uint64_t)* ptr){
	uint64_t l;
	for(;;){
		l = atomic_load_explicit(ptr, memory_order_acquire);
		if(l) return l;
		thread_yield();
	}
}
// Release a time lock and set the last used time. See `_time_lock_acq`
static void _time_lock_rel(atomic(uint64_t)* ptr, uint64_t l){
	atomic_store_explicit(ptr, l, memory_order_release);
}

typedef union{
	struct{
		ip_addr_t addr;
		union{ struct{ uint16_t port_le, mtu_le; }; uint32_t port_mtu_packed_le; };
		uint32_t id[5];
	};
	uint32_t dwords[10];
} hivemind_pipe_t;

static_assert(alignof(hivemind_pipe_t) <= 4);
static_assert(sizeof(hivemind_pipe_t) == 40);

#define SEND_BURST 6000
#define SEND_TICK 2000 // 2ms in useconds

// Resolve a 96-bit sequence number from the low 32 bits and a reference sequence number
// The returned sequence number is within +/- 2^31 of the reference sequence number
static inline void _resolve_seq(uint64_t* lo, uint32_t* hi, uint32_t seq){
	uint64_t lo1 = *lo, lo2 = (lo1 & 0xFFFFFFFF00000000) | seq;
	*lo = lo2 + ((lo2-lo1+(0x80000000))&0xFFFFFFFF00000000);
	*hi += (lo2>>32)-(lo1>>32);
}

// [IP]/port/mtu/time/rand_b64
static const size_t HIVEMIND_PIPE_STR_MAX_LEN = IP_STR_MAX_LEN + /* port, mtu */ 12 + /* time */ 18 + /* rand_b64 */ 19;

static inline void _hivemind_remote_cleanup_recv(struct _hivemind_remote* state){
	if(state->cur_packet) free(state->cur_packet), state->cur_packet = 0;
	ring_buffer_clear(&state->recv_queue);
}

static void _hivemind_remote_cleanup_send(struct _hivemind_remote* state){
	struct _send_packet* p = state->send_order_start;
	while(p){
		struct _send_packet* p2 = p->next;
		free(p); p = p2;
	}
	state->send_order_start = 0; state->send_order_end = &state->send_order_start;
	state->send_window = 0;
	ring_iterator_t q = ring_buffer_iterator(&state->send_queue, state->unsent_i, -1ull);
	while(ring_iterator_next(&q, &p, sizeof(p), true))
		free(p);
	
	ring_buffer_clear(&state->send_queue);
	state->unsent_i = 0;
}

static_assert(SIZE_MAX <= UINT64_MAX);
typedef uint64_t sfat_pointer_t;
#define sfat_pack(p, s) ((uintptr_t)(p)<<16|(s))
#define sfat_get(p) (uint8_t*)((uintptr_t)(p)>>16)
#define sfat_size(p) ((uintptr_t)(p)&0xFFFF)