#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <math.h>
#include "dbg.h"

#if defined(__has_c_attribute)
#if __has_c_attribute(likely)
	#define unlikely(x) (x) [[unlikely]]
	#define likely(x) (x) [[likely]]
#endif
#endif
#if !defined(likely) && (defined(__clang__) || defined(__GNUC__))
	#define unlikely(x) (__builtin_expect(!!(x),0))
	#define likely(x) (__builtin_expect(!!(x),1))
	#define unreachable() __builtin_unreachable()
#else
#ifdef _MSC_VER
	#define unreachable() __assume(0)
#else
	#define unreachable() (1/0)
#endif
	#define unlikely(x) (x)
	#define likely(x) (x)
#endif

#undef static_assert
#define _Static_assert(x,y,...) _Static_assert(x,y)
#define static_assert(...) _Static_assert(__VA_ARGS__,#__VA_ARGS__)

#ifdef _MSC_VER
#include <stdarg.h>
int asprintf(char** strp, const char* fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	// compute required length (excluding null terminator)
	int len = _vscprintf(fmt, ap);
	va_end(ap);
	if(len < 0){ *strp = NULL; return -1; }

	char* buf = (char*) malloc(len + 1);
	*strp = buf;
	if(!buf) return -1;
	va_start(ap, fmt);
	vsnprintf(buf, len+1, fmt, ap);
	va_end(ap);
	*strp = buf;
	return len;
}
int __shim_bsrz(size_t x){
	unsigned long index;
#if SIZE_MAX == UINT_MAX
	if(_BitScanReverse(&index, x)) return index+1;
#else
	if(_BitScanReverse64(&index, x)) return index+1;
#endif
	__assume(0);
}
#define size_magn(x) __shim_bsrz(x)
#define templated static __forceinline inline
#define noinline static __declspec(noinline)
#else
#if SIZE_MAX == UINT_MAX
#define size_magn(x) ((size_t)(__INT_WIDTH__-__builtin_clz(x)))
#else
#define size_magn(x) ((size_t)(__LLONG_WIDTH__-__builtin_clzll(x)))
#endif
#define templated static __attribute__((always_inline)) inline
#define noinline static __attribute__((noinline))
#endif

static_assert(sizeof(size_t) == sizeof(void*));

// A fast approximation to 2^x, with a maximum relative error of about 0.088%
static inline float fast_exp2f(float x){
	float xi = floorf(x); x -= xi;
	x *= 0.66596094f + 0.32993240f*x;
	return ldexpf(1.f+x, (int)xi);
}

// Poor man's exponential. between 2^n and 2^(n+1), the function is completely linear. Maximum relative error ~6.15%
static inline float discrete_exp2f(float x){
	float xi = floorf(x);
	return ldexpf(1.f+(x-xi), (int)xi);
}
// Poor man's logarithm. See also: `discrete_exp2f` (Poor man's exponential)
static inline float discrete_log2f(float x){
	int xi; x = frexpf(x, &xi);
	return (float)(xi-1) + x*2.f-1.f;
}

#if SIZE_MAX >= UINT64_MAX
typedef struct ring_buffer_t{
	union{ char* data; char data_i[sizeof(char*)]; };
	size_t cap_exp:8;
	size_t l:sizeof(size_t)*CHAR_BIT-8; size_t size;
} ring_buffer_t;
typedef struct ring_iterator_t{
	char *head, *end;
	size_t cap_exp:8, remaining:sizeof(size_t)*CHAR_BIT-8;
} ring_iterator_t;
static_assert(sizeof(ring_buffer_t) == sizeof(size_t) * 3);
#else
typedef struct ring_buffer_t{
	union{ char* data; char data_i[sizeof(char*)]; };
	size_t cap_exp, l, size;
} ring_buffer_t;
typedef struct ring_iterator_t{
	char *head, *end;
	size_t cap_exp, remaining;
} ring_iterator_t;
static_assert(sizeof(ring_buffer_t) == sizeof(size_t) * 4);
#endif

templated size_t ring_buffer_size(ring_buffer_t* obj){ return obj->size; }

noinline char* _ring_buffer_grow(ring_buffer_t* obj, char* dat, size_t* cap, size_t used2){
	size_t cap2 = 1ull<<(int)(obj->cap_exp = size_magn((used2-1)|31));
	char* dat2 = (char*) malloc(cap2);
	if unlikely(!dat2) abort();
	size_t l = obj->l, size = obj->size, cap_ = *cap;
	if(l+size > cap_){
		memcpy(dat2, dat+l, cap_-l);
		memcpy(dat2+(cap_-l), dat, l+size-cap_);
	}else memcpy(dat2, dat+l, size);
	obj->l = 0;
	if(dat!=obj->data_i) free(dat);
	obj->data = dat2; *cap = cap2;
	return dat2;
}

templated size_t ring_buffer_push_garbage(ring_buffer_t* obj, size_t sz, bool _aligned){
	size_t cap = obj->cap_exp; char* dat;
	if(!cap) cap = sizeof(char*), dat = obj->data_i;
	else cap = 1ull<<(int)cap, dat = obj->data;
	size_t size = obj->size, used2 = size+sz;
	if(_aligned) assert(sz <= cap-(obj->l+size) && !(sz&(sz-1)), "Alignment condition violated");
	if(used2 > cap)
		_ring_buffer_grow(obj, dat, &cap, used2);
	obj->size = used2;
	return size;
}

templated void ring_buffer_push(ring_buffer_t* obj, void* d, size_t sz, bool aligned){
	size_t cap = obj->cap_exp; char* dat;
	if(!cap) cap = sizeof(char*), dat = obj->data_i;
	else cap = 1ull<<(int)cap, dat = obj->data;
	size_t size = obj->size, used2 = size+sz;
	if(used2 > cap)
		dat = _ring_buffer_grow(obj, dat, &cap, used2);
	obj->size = used2;
	size_t r = (obj->l+size)&(cap-1);
	if(!aligned && sz > cap-r){
		size_t sz2 = cap-r;
		memcpy(dat+r, d, sz2);
		memcpy(dat, (char*)d+sz2, sz-sz2);
	}else{
		if(aligned) assert(sz <= cap-r && !(sz&(sz-1)), "Alignment condition violated");
		memcpy(dat+r, d, sz);
	}
}

templated void ring_buffer_push_memset(ring_buffer_t* obj, char v, size_t sz, bool aligned){
	size_t cap = obj->cap_exp; char* dat;
	if(!cap) cap = sizeof(char*), dat = obj->data_i;
	else cap = 1ull<<(int)cap, dat = obj->data;
	size_t size = obj->size, used2 = size+sz;
	if(used2 > cap)
		dat = _ring_buffer_grow(obj, dat, &cap, used2);
	obj->size = used2;
	size_t r = (obj->l+size)&(cap-1);
	if(!aligned && sz > cap-r){
		size_t sz2 = cap-r;
		memset(dat+r, v, sz2);
		memset(dat, v, sz-sz2);
	}else{
		if(aligned) assert(sz <= cap-r && !(sz&(sz-1)), "Alignment condition violated");
		memset(dat+r, v, sz);
	}
}

noinline void _ring_buffer_shrink(ring_buffer_t* obj, char* dat, size_t cap){
	char* dat2; size_t used2 = obj->size;
	if(used2 <= sizeof(char*)){
		obj->cap_exp = 0;
		dat2 = obj->data_i;
	}else{
		dat2 = obj->data = (char*) malloc(1ull<<(int)(obj->cap_exp = size_magn((used2-1)|31)));
		if unlikely(!dat2) abort();
	}
	size_t l = obj->l;
	if unlikely(used2 > cap-l){
		memcpy(dat2, dat+l, cap-l);
		memcpy(dat2+(cap-l), dat, l+used2-cap);
	}else memcpy(dat2, dat+l, used2);
	obj->l = 0;
	free(dat);
}

templated void ring_buffer_shift_discard(ring_buffer_t* obj, size_t sz, bool _aligned){
	size_t cap = obj->cap_exp; char* dat;
	if(!cap) cap = sizeof(char*), dat = obj->data_i;
	else cap = 1ull<<(int)cap, dat = obj->data;
	assert(sz <= obj->size, "Size underflow");
	obj->l = (obj->l+sz)&(cap-1);
	size_t used2 = obj->size -= sz;
	if(_aligned) assert(sz <= (cap-obj->l) && !(sz&(sz-1)), "Alignment condition violated");
	if(cap > sizeof(char*) && used2 <= (cap>>2))
		_ring_buffer_shrink(obj, dat, cap);
}

templated void ring_buffer_shift(ring_buffer_t* obj, void* d, size_t sz, bool aligned){
	size_t cap = obj->cap_exp; char* dat;
	if(!cap) cap = sizeof(char*), dat = obj->data_i;
	else cap = 1ull<<(int)cap, dat = obj->data;
	assert(sz <= obj->size, "Size underflow");
	size_t l = obj->l;
	if(!aligned && sz > cap-l){
		size_t sz2 = cap-l;
		memcpy(d, dat+l, sz2);
		memcpy((char*)d+sz2, dat, sz-sz2);
	}else{
		if(aligned) assert(sz <= cap-l && !(sz&(sz-1)), "Alignment condition violated");
		memcpy(d, dat+l, sz);
	}
	obj->l = (l+sz)&(cap-1);
	size_t used2 = obj->size -= sz;
	if(cap > sizeof(char*) && used2 <= (cap>>2))
		_ring_buffer_shrink(obj, dat, cap);
}

templated void ring_buffer_get(ring_buffer_t* obj, size_t i, void* d, size_t sz, bool aligned){
	size_t cap = obj->cap_exp; char* dat;
	if(!cap) cap = sizeof(char*), dat = obj->data_i;
	else cap = 1ull<<(int)cap, dat = obj->data;
	assert(i+sz <= obj->size, "Index overflow");
	size_t r = (obj->l+i)&(cap-1);
	if(!aligned && sz > cap-r){
		size_t sz2 = cap-r;
		memcpy(d, dat+r, sz2);
		memcpy((char*)d+sz2, dat, sz-sz2);
	}else{
		if(aligned) assert(sz <= cap-r && !((i|sz)&(sz-1)), "Alignment condition violated");
		memcpy(d, dat+r, sz);
	}
}

templated void ring_buffer_set(ring_buffer_t* obj, size_t i, void* d, size_t sz, bool aligned){
	size_t cap = obj->cap_exp; char* dat;
	if(!cap) cap = sizeof(char*), dat = obj->data_i;
	else cap = 1ull<<(int)cap, dat = obj->data;
	assert(i+sz <= obj->size, "Index overflow");
	size_t r = (obj->l+i)&(cap-1);
	if(!aligned && sz > cap-r){
		size_t sz2 = cap-r;
		memcpy(dat+r, d, sz2);
		memcpy(dat, (char*)d+sz2, sz-sz2);
	}else{
		if(aligned) assert(sz <= cap-r && !((i|sz)&(sz-1)), "Alignment condition violated");
		memcpy(dat+r, d, sz);
	}
}

static inline ring_iterator_t ring_buffer_iterator(ring_buffer_t* obj, size_t i, size_t count){
	size_t cap_exp = obj->cap_exp; char* dat;
	if(!cap_exp) cap_exp = size_magn(sizeof(char*)-1), dat = obj->data_i;
	else dat = obj->data;
	size_t cap = 1ull<<(int)cap_exp;
	size_t l = (obj->l+i)&(cap-1); if(count > obj->size-i) count = obj->size-i;
	if(l + count <= cap) return (ring_iterator_t){dat+l, dat+l+count, 0, count};
	return (ring_iterator_t){dat+l, dat+cap, cap_exp, count};
}

templated size_t ring_iterator_next(ring_iterator_t* obj, void* d, size_t sz, bool aligned){
	char *head = obj->head;
	if(head >= obj->end){
		size_t cap = obj->cap_exp;
		if(cap) obj->head = head -= 1ull<<(int)cap, obj->cap_exp = 0, obj->end = head+obj->remaining;
		else return false;
	}
	assert(sz <= obj->remaining, "Iterator index overflow");
	if(!aligned && head+sz > obj->end){
		size_t sz2 = (size_t)(obj->end-obj->head);
		memcpy(d, head, sz2);
		size_t cap = obj->cap_exp; // assumed, overrun is UB
		obj->head = head -= 1ull<<(int)cap, obj->cap_exp = 0, obj->end = head+obj->remaining-sz2;
		memcpy((char*)d+sz2, head, sz-sz2);
	}else{
		if(aligned) assert(head+sz <= obj->end && !(sz&(sz-1)), "Alignment condition violated");
		memcpy(d, head, sz);
		obj->head = head+sz;
	}
	return obj->remaining -= sz;
}

templated void ring_buffer_destroy(ring_buffer_t* obj){
	if(obj->cap_exp) free(obj->data);
	if(DEBUG) memset(obj, 0xDE, sizeof(*obj));
}



#if SIZE_MAX >= UINT64_MAX
typedef struct array_buffer_t{
	union{ char* data; char data_i[sizeof(char*)]; };
	size_t cap_exp:8, size:sizeof(size_t)*CHAR_BIT-8;
} array_buffer_t;
static_assert(sizeof(array_buffer_t) == sizeof(size_t) * 2);
#else
typedef struct array_buffer_t{
	union{ char* data; char data_i[sizeof(char*)]; };
	size_t cap_exp, size;
} array_buffer_t;
static_assert(sizeof(array_buffer_t) == sizeof(size_t) * 3);
#endif
typedef struct array_iterator_t{
	char *head; size_t remaining;
} array_iterator_t;

templated size_t array_buffer_size(array_buffer_t* obj){ return obj->size; }
templated void* array_buffer_data(array_buffer_t* obj){ return obj->cap_exp?obj->data:obj->data_i; }

noinline char* _array_buffer_grow(array_buffer_t* obj, char* dat, size_t* cap, size_t used2){
	char* dat2 = (char*) malloc(*cap = 1ull<<(int)(obj->cap_exp = size_magn((used2-1)|31)));
	if unlikely(!dat2) abort();
	memcpy(dat2, dat, obj->size);
	if(dat!=obj->data_i) free(dat);
	obj->data = dat2;
	return dat2;
}

noinline void _array_buffer_shrink(array_buffer_t* obj){
	char* dat2; size_t used2 = obj->size;
	char* dat = obj->data;
	if(used2 <= sizeof(char*)){
		obj->cap_exp = 0;
		dat2 = obj->data_i;
	}else{
		dat2 = obj->data = (char*) malloc(1ull<<(int)(obj->cap_exp = size_magn((used2-1)|31)));
		if unlikely(!dat2) abort();
	}
	memcpy(dat2, dat, used2);
	free(dat);
}

templated void array_buffer_setsize_garbage(array_buffer_t* obj, size_t sz){
	size_t cap = obj->cap_exp, size = obj->size;
	if(sz > size){
		char* dat;
		if(!cap) cap = sizeof(char*), dat = obj->data_i;
		else cap = 1ull<<(int)cap, dat = obj->data;
		if(sz > cap)
			_array_buffer_grow(obj, dat, &cap, sz);
		obj->size = sz;
	}else if(sz < size){
		obj->size = sz;
		if(cap && sz <= (1ull<<(int)(cap-2)))
			_array_buffer_shrink(obj);
	}
}

templated void* array_buffer_push_garbage(array_buffer_t* obj, size_t sz){
	size_t cap = obj->cap_exp; char* dat;
	if(!cap) cap = sizeof(char*), dat = obj->data_i;
	else cap = 1ull<<(int)cap, dat = obj->data;
	size_t size = obj->size, used2 = size+sz;
	if(used2 > cap)
		dat = _array_buffer_grow(obj, dat, &cap, used2);
	obj->size = used2;
	return dat+size;
}

templated void array_buffer_push(array_buffer_t* obj, void* d, size_t sz){
	size_t cap = obj->cap_exp; char* dat;
	if(!cap) cap = sizeof(char*), dat = obj->data_i;
	else cap = 1ull<<(int)cap, dat = obj->data;
	size_t size = obj->size, len2 = size+sz;
	if(len2 > cap)
		dat = _array_buffer_grow(obj, dat, &cap, len2);
	obj->size = len2;
	memcpy(dat+size, d, sz);
}

templated void array_buffer_push_memset(array_buffer_t* obj, int v, size_t sz){
	size_t cap = obj->cap_exp; char* dat;
	if(!cap) cap = sizeof(char*), dat = obj->data_i;
	else cap = 1ull<<(int)cap, dat = obj->data;
	size_t size = obj->size, len2 = size+sz;
	if(len2 > cap)
		dat = _array_buffer_grow(obj, dat, &cap, len2);
	obj->size = len2;
	memset(dat+size, v, sz);
}

templated void array_buffer_pop_discard(array_buffer_t* obj, size_t sz){
	size_t cap = obj->cap_exp, used2 = obj->size -= sz;
	if(cap && used2 <= (1ull<<(int)(cap-2)))
		_array_buffer_shrink(obj);
}

templated void array_buffer_pop(array_buffer_t* obj, void* d, size_t sz){
	size_t cap = obj->cap_exp;
	if(!cap){
		memcpy(d, &obj->data, sz);
		obj->size -= sz;
	}else{
		memcpy(d, obj->data, sz);
		if((obj->size -= sz) <= (1ull<<(int)(cap-2)))
			_array_buffer_shrink(obj);
	}
}

templated void array_buffer_get(array_buffer_t* obj, size_t i, void* d, size_t sz){
	memcpy(d, (obj->cap_exp ? obj->data : obj->data_i)+i, sz);
}

templated void array_buffer_set(array_buffer_t* obj, size_t i, void* d, size_t sz){
	memcpy((obj->cap_exp ? obj->data : obj->data_i)+i, d, sz);
}

static inline array_iterator_t array_buffer_iterator(array_buffer_t* obj, size_t i, size_t count){
	if(count > obj->size-i) count = obj->size-i;
	return (array_iterator_t){(obj->cap_exp ? obj->data : obj->data_i)+i, count};
}

templated size_t array_iterator_next(array_iterator_t* obj, void* d, size_t sz){
	char *head = obj->head;
	memcpy(d, head, sz);
	obj->head = head+sz;
	return obj->remaining -= sz;
}

templated void array_buffer_destroy(array_buffer_t* obj){
	if(obj->cap_exp) free(obj->data);
	if(DEBUG) memset(obj, 0xDE, sizeof(*obj));
}

// A shared mutex. Any amount of threads may shared-acquire, only one thread at a time can exclusive-acquire, and not while any thread has the shared lock acquired. This is useful for many-readers-few-writers scenarios, where an exclusive mutex for read-only operations is excessive
typedef lock_t shared_lock_t;
static_assert(sizeof(shared_lock_t) <= CACHE_LINE); // if this was false that would be pretty insane

#define SHARED_LOCK_MAX (LOCK_MAX>>1)
#define SHARED_LOCK_EXCL_BIT (LOCK_MAX&~SHARED_LOCK_MAX)

templated void shared_lock_init(shared_lock_t* s){
	// lock_t is semaphore style, we specify how many slots we have
	atomic_init(s, LOCK_MAX);
}
// Acquire the "shared" part of a shared lock. This will block if any thread is trying to or has already obtained an exclusive lock. This will also cause all future exclusive lock acquires to block until the shared lock is released
templated void shared_lock_acquire(shared_lock_t* s){
	lock_wait_acquire(s, SHARED_LOCK_EXCL_BIT+1, 1);
}
// Wait for the "shared" part of a shared lock to become available, if it isn't. This will block if any thread is trying to or has already obtained an exclusive lock. No lock is acquired, another thread may immediately acquire the lock while this function returns, you should not call `shared_lock_release` after this.
templated void shared_lock_wait(shared_lock_t* s){
	lock_wait(s, SHARED_LOCK_EXCL_BIT+1);
}
// Try to acquire the "shared" part of a shared lock. This will return false if any thread is trying to or has already obtained an exclusive lock. See `shared_lock_acquire`
templated bool shared_lock_try_acquire(shared_lock_t* s){
	return lock_test_and_acquire(s, SHARED_LOCK_EXCL_BIT+1, 1);
}
// Release the "shared" part of a shared lock. Releasing more times than was acquired (i.e, calling this function when no shared part is currently acquired) is UB
templated void shared_lock_release(shared_lock_t* s){
	assert((lock_fetch(s)&SHARED_LOCK_MAX) < SHARED_LOCK_MAX, "shared_lock_release() called on shared_lock_t with no shared part acquired");
	lock_release(s, 1);
}
// Upgrade a "shared" lock to an exclusive one. This operation may be performed without ever releasing the shared part of the lock, in which case it will return `true`. Note that this cannot be guaranteed due to the possibility of deadlocks. This function avoids deadlocks by briefly dropping the shared part if necessary, in which case it will return `false`. In all cases, upgrading when no shared part was acquired to begin with is UB
templated bool shared_lock_upgrade(shared_lock_t* s){
	assert((lock_fetch(s)&SHARED_LOCK_MAX) < SHARED_LOCK_MAX, "shared_lock_upgrade() called on shared_lock_t with no shared part acquired");
	bool f = true;
	if(!lock_try_acquire(s, SHARED_LOCK_EXCL_BIT)){
		lock_release(s, 1);
		lock_wait_acquire(s, SHARED_LOCK_EXCL_BIT, SHARED_LOCK_EXCL_BIT);
		f = false;
	}
	lock_acquire(s, (LOCK_MAX&~SHARED_LOCK_EXCL_BIT)-f);
	return f;
}
// Try to upgrade a "shared" lock to an exclusive one. This operation is performed without ever releasing the shared part of the lock. If another thread owns or is trying to obtain the exclusive lock, there is a possibility of deadlocks, and the function will return false (it follows that this function cannot block on the exclusive lock, however it can block if other threads hold the shared part of the lock). In all cases, upgrading when no shared part was acquired to begin with is UB
templated bool shared_lock_try_upgrade(shared_lock_t* s){
	assert((lock_fetch(s)&SHARED_LOCK_MAX) < SHARED_LOCK_MAX, "shared_lock_upgrade() called on shared_lock_t with no shared part acquired");
	return lock_try_acquire(&s, LOCK_MAX-1);
}
// Acquire the "exclusive" part of a shared lock. This will block if any thread is trying to or has already obtained an exclusive lock. This will also cause all future shared/exclusive lock acquires to block until the exclusive lock is released
templated void exclusive_lock_acquire(shared_lock_t* s){
	lock_wait_acquire(s, SHARED_LOCK_EXCL_BIT, SHARED_LOCK_EXCL_BIT);
	lock_acquire(s, SHARED_LOCK_MAX);
}
// Wait for the "exclusive" part of a shared lock to become available. This will block if any thread is trying to or has already obtained an exclusive lock. No lock is acquired, another thread may immediately acquire the lock while this function returns, you should not call `exclusive_lock_release` after this.
templated void exclusive_lock_wait(shared_lock_t* s){
	lock_wait_acquire(s, SHARED_LOCK_EXCL_BIT, SHARED_LOCK_EXCL_BIT);
	lock_wait(s, SHARED_LOCK_MAX);
	lock_release_explicit(s, SHARED_LOCK_EXCL_BIT, memory_order_relaxed);
}
// Try to acquire the "exclusive" part of a shared lock. This will return false if any thread is trying to or has already obtained an exclusive lock. See `exclusive_lock_acquire`
templated bool exclusive_lock_try_acquire(shared_lock_t* s){
	return lock_try_acquire(s, LOCK_MAX);
}
// Release the "exclusive" part of a shared lock. Releasing when no exclusive part was acquired is UB
templated void exclusive_lock_release(shared_lock_t* s){
	assert(!lock_fetch(s), "exclusive_lock_release() called on shared_lock_t with no exclusive part acquired");
	lock_release(s, LOCK_MAX);
}
// Downgrade from an "exclusive" lock to a shared lock, without releasing the shared part. Unlike `shared_lock_upgrade`, this does not have the same deadlock danger, and will therefore always succeed. Downgrading when no exclusive part was acquired is UB
templated void exclusive_lock_downgrade(shared_lock_t* s){
	assert(!lock_fetch(s), "exclusive_lock_downgrade() called on shared_lock_t with no exclusive part acquired");
	lock_release(s, LOCK_MAX-1);
}

/*// Incomplete hashmap implementation
typedef union _hashmap_ptr{ union _hashmap_ptr* nextp; uintptr_t value; } _hashmap_ptr;
#if SIZE_MAX >= UINT64_MAX
typedef struct hashmap_t{
	_hashmap_ptr* entries;
	size_t b_exp:8, size:sizeof(size_t)*CHAR_BIT-8;
} hashmap_t;
static_assert(sizeof(hashmap_t) == sizeof(size_t) * 2);
#else
typedef struct hashmap_t{
	_hashmap_ptr* entries;
	size_t b_exp, size;
} hashmap_t;
static_assert(sizeof(hashmap_t) == sizeof(size_t) * 3);
#endif
typedef struct hash_iterator_t{
	_hashmap_ptr *bucket_start, *last_bucket;
	_hashmap_ptr *cur; size_t adv;
} hash_iterator_t;
static_assert(sizeof(hash_iterator_t) == sizeof(size_t) * 4);

#define adv_aligned(p, a) (((p)+(a)-1)&~(a))

typedef struct hashmap_descriptor_t{
	size_t size, align;
	uint64_t (*hash)(void*);
	uint64_t (*hash_value)(void*);
	bool (*compare)(void* key, void* candidate);
	void (*move)(void* new_, void* old);
} hashmap_descriptor_t;

noinline void _hashmap_grow1(hashmap_t* map, hashmap_descriptor_t* desc){
	unsigned bexp = map->b_exp++;
	size_t new_prefix = (1<<bexp)+1;
	size_t alloc_sz = adv_aligned(sizeof(_hashmap_ptr)*(new_prefix+(4<<bexp)), desc->align) + desc->size*(4<<bexp);
	_hashmap_ptr* entries2 = (_hashmap_ptr*)(desc->align > alignof(max_align_t) ? aligned_alloc(alloc_sz, desc->align) : malloc(alloc_sz));
	if(!entries2) abort();
	memset(entries2, 0, sizeof(_hashmap_ptr)*((1<<bexp)+1));
	size_t old_prefix = (1<<(bexp-1))+1;
	char* old_heap = (char*)map->entries+adv_aligned(sizeof(_hashmap_ptr)*(old_prefix+(4<<(bexp-1))), desc->align);
	char* new_heap = (char*)entries2+adv_aligned(sizeof(_hashmap_ptr)+(new_prefix+(4<<bexp)), desc->align);
	size_t newsz = 0;
	// savenge move
	for(size_t i = new_prefix-1; i; i--){
		_hashmap_ptr ptr = map->entries[i];
		while(ptr.value){
			char* old = old_heap+(ptr.nextp-map->entries-old_prefix)*desc->size;
			if(desc->move) desc->move(new_heap, old);
			else memcpy(new_heap, old, desc->size);
			uint64_t h = desc->hash_value(new_heap), h2 = (h>>(64-bexp))+1; h &= sizeof(uintptr_t)-1;
			_hashmap_ptr next = {.value = entries2[h2].value+h};
			entries2[new_prefix+newsz] = next;
			entries2[h2].nextp = entries2+new_prefix+newsz;
			new_heap += desc->size; newsz++;
			ptr = *ptr.nextp;
		}
	}
	free(map->entries);
	map->size = newsz;
	map->entries = entries2;
}

templated hash_iterator_t hashmap_find_iterator(const hashmap_t* map, hashmap_descriptor_t desc, void* key){
	unsigned bexp = map->b_exp;
	if(!bexp) return (hash_iterator_t){};
	bexp--;
	uint64_t h = desc.hash(key);
	_hashmap_ptr* bucket = &map->entries[(bexp ? h>>(64-bexp) : 0)+1];
	_hashmap_ptr ptr = *bucket;
	_hashmap_ptr* optr = ptr.nextp;
	h &= sizeof(uintptr_t)-1;
	while(ptr.value){
		ptr = *optr;
		if((ptr.value&(sizeof(uintptr_t)-1)) == h){
			// Maybe match!
			size_t prefix = (1<<bexp)+1;
			char* heap = (char*)map->entries+adv_aligned(sizeof(_hashmap_ptr)*(prefix+(4<<bexp)), desc.align);
			if(desc.compare(key, (void*)(heap + (optr-map->entries - prefix)*desc.size))){
				return (hash_iterator_t){bucket, map->entries+prefix, optr, (4<<bexp)};
			}
		}
		optr = ptr.nextp;
	}
	return (hash_iterator_t){};
}

templated bool hashmap_iterator_is_valid(const hash_iterator_t* it){ return (bool)it->cur.value; }

templated void* hashmap_find(const hashmap_t* map, hashmap_descriptor_t desc, void* key){
	unsigned bexp = map->b_exp;
	if(!bexp) return 0;
	bexp--;
	uint64_t h = desc.hash(key);
	_hashmap_ptr ptr = map->entries[(bexp ? h>>(64-bexp) : 0)+1];
	_hashmap_ptr* optr = ptr.nextp;
	h &= sizeof(uintptr_t)-1;
	while(ptr.value){
		ptr = *optr;
		if((ptr.value&(sizeof(uintptr_t)-1)) == h){
			// Maybe match!
			size_t prefix = (1<<bexp)+1;
			char* heap = (char*)map->entries+adv_aligned(sizeof(_hashmap_ptr)*(prefix+(4<<bexp)), desc.align);
			void* candidate = (void*)(heap + (optr-map->entries - prefix)*desc.size);
			if(desc.compare(key, candidate)) return candidate;
		}
		optr = ptr.nextp;
	}
	return 0;
}

templated void* hashmap_insert(hashmap_t* map, hashmap_descriptor_t desc, void* key){
	unsigned bexp = map->b_exp;
	uint64_t h = desc.hash(key);
	if(!bexp){
		size_t alloc_sz = adv_aligned(sizeof(_hashmap_ptr)*6, desc.align) + desc.size*4;
		map->entries = (_hashmap_ptr*)(desc.align > alignof(max_align_t) ? aligned_alloc(alloc_sz, desc.align) : malloc(alloc_sz));
		map->b_exp = 1; map->size = 1;
		memset(map->entries, 0, sizeof(_hashmap_ptr)*6);
		map->entries[1].nextp = &map->entries[2];
		map->entries[2].value = h&(sizeof(uintptr_t)-1);
		return (char*)map->entries + adv_aligned(sizeof(_hashmap_ptr)*6, desc.align);
	}
	bexp--;
	size_t prefix = (1<<bexp)+1;
	size_t idx = map->entries[0].value;
	if(idx){ // consume from free list
		map->entries[0] = map->entries[idx];
	}else{
		if(map->size >= (4<<bexp))
			_hashmap_grow1(map, &desc);
		idx = map->size++ + prefix;
	}
	uint64_t h2 = (h>>(64-bexp))+1; h &= sizeof(uintptr_t)-1;
	map->entries[idx].nextp = map->entries[h2].nextp+h;
	map->entries[h2].nextp = map->entries+idx;
	char* heap = (char*)map->entries+adv_aligned(sizeof(_hashmap_ptr)*(prefix+(4<<bexp)), desc.align);
	return heap+(idx-prefix)*desc.size;
}

templated bool hashmap_find_or_insert(hashmap_t* map, hashmap_descriptor_t desc, void* key, void** out){
	unsigned bexp = map->b_exp;
	uint64_t h = desc.hash(key);
	if(!bexp){
		size_t alloc_sz = adv_aligned(sizeof(_hashmap_ptr)*6, desc.align) + desc.size*4;
		map->entries = (_hashmap_ptr*)(desc.align > alignof(max_align_t) ? aligned_alloc(alloc_sz, desc.align) : malloc(alloc_sz));
		map->b_exp = 1; map->size = 1;
		memset(map->entries, 0, sizeof(_hashmap_ptr)*6);
		map->entries[1].nextp = &map->entries[2];
		map->entries[2].value = h&(sizeof(uintptr_t)-1);
		*out = (char*)map->entries + adv_aligned(sizeof(_hashmap_ptr)*6, desc.align);
		return true;
	}
	bexp--;
	size_t prefix = (1<<bexp)+1;
	uint64_t h2 = (h>>(64-bexp))+1; h &= 7;
	_hashmap_ptr ptr = map->entries[h2];
	_hashmap_ptr* optr = ptr.nextp;
	while(optr){
		ptr = *optr;
		if((ptr.value&7) == h){
			// Maybe match!
			char* heap = (char*)map->entries+adv_aligned(sizeof(_hashmap_ptr)*(prefix+(4<<bexp)), desc.align);
			void* candidate = (void*)(heap + (optr-map->entries - prefix)*desc.size);
			if(desc.compare(key, candidate)){ *out = candidate; return false; }
		}
		optr = ptr.nextp;
	}
	size_t idx = map->entries[0].value;
	if(idx){ // consume from free list
		map->entries[0] = map->entries[idx];
	}else{
		if(map->size >= (4<<bexp))
			_hashmap_grow1(map, &desc);
		idx = map->size++ + prefix;
	}
	map->entries[idx].nextp = map->entries[h2].nextp+h;
	map->entries[h2].nextp = map->entries+idx;
	char* heap = (char*)map->entries+adv_aligned(sizeof(_hashmap_ptr)*(prefix+(4<<bexp)), desc.align);
	*out = heap+(idx-prefix)*desc.size;
	return true;
}

templated bool hashmap_delete(hashmap_t* map, hashmap_descriptor_t desc, void* key){

}


templated void hashmap_destroy(hashmap_t* map, hashmap_descriptor_t _){
	if(map->b_exp) free(map->entries);
}*/

#if SIZE_MAX >= UINT64_MAX
typedef struct hash_table_t{ uintptr_t cap_exp:8, data:sizeof(uintptr_t)*CHAR_BIT-8; } hash_table_t;
static_assert(sizeof(hash_table_t) == sizeof(size_t));
#else
typedef struct hash_table_t{ uintptr_t cap_exp, data; } hash_table_t;
static_assert(sizeof(hash_table_t) == sizeof(size_t) * 2);
#endif

templated void* hash_table_find(const hash_table_t* t, uint64_t hash){
	return t->cap_exp ? ((void**)t->data)[hash&(1<<(t->cap_exp)-1)] : t->data;
}
templated void hash_table_put(hash_table_t* t, uint64_t hash, void* v){
	if(t->cap_exp) ((void**)t->data)[hash&(1<<(t->cap_exp)-1)] = v;
	else t->data = (uintptr_t)v;
}
templated void hash_table_set_rank(hash_table_t* t, unsigned rank){
	if(t->cap_exp) free((void*)t->data);
	t->cap_exp = rank;
	if(rank){
		void* d = malloc(sizeof(void*)<<rank);
		memset(d, 0, sizeof(void*)<<rank);
		t->data = (uintptr_t)d;
	}else t->data = 0;
}

static_assert(SIZE_MAX >= UINT32_MAX && SIZE_MAX <= UINT64_MAX);
typedef uint64_t sfat_pointer_t;
#define sfat_pack(p, s) ((uintptr_t)(p)<<16|(s))
#define sfat_get(p) (uint8_t*)((uintptr_t)(p)>>16)
#define sfat_size(p) ((uintptr_t)(p)&0xFFFF)