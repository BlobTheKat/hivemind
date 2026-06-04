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

#if SIZE_MAX == UINT64_MAX
typedef struct ring_buffer_t{
	char* data;
	size_t cap_exp:8;
	size_t l:(sizeof(size_t)*CHAR_BIT)-8; size_t size;
} ring_buffer_t;
typedef struct ring_iterator_t{
	char *head, *end;
	size_t cap_exp:8, remaining:56;
} ring_iterator_t;
static_assert(sizeof(ring_buffer_t) == sizeof(size_t) * 3);
#else
typedef struct ring_buffer_t{
	char* data;
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
	if(dat!=(char*)&obj->data) free(dat);
	obj->data = dat2; *cap = cap2;
	return dat2;
}

templated size_t ring_buffer_push_garbage(ring_buffer_t* obj, size_t sz, bool _aligned){
	size_t cap = obj->cap_exp; char* dat;
	if(!cap) cap = sizeof(char*), dat = (char*)&obj->data;
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
	if(!cap) cap = sizeof(char*), dat = (char*)&obj->data;
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
	if(!cap) cap = sizeof(char*), dat = (char*)&obj->data;
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
		dat2 = (char*)&obj->data;
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
	if(!cap) cap = sizeof(char*), dat = (char*)&obj->data;
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
	if(!cap) cap = sizeof(char*), dat = (char*)&obj->data;
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
	if(!cap) cap = sizeof(char*), dat = (char*)&obj->data;
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
	if(!cap) cap = sizeof(char*), dat = (char*)&obj->data;
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
	if(!cap_exp) cap_exp = size_magn(sizeof(char*)-1), dat = (char*)&obj->data;
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

templated void ring_buffer_clear(ring_buffer_t* obj){
	if(obj->cap_exp) free(obj->data), obj->cap_exp = 0;
	obj->size = obj->l = 0;
}
templated void ring_buffer_destroy(ring_buffer_t* obj){
	if(obj->cap_exp) free(obj->data);
	if(DEBUG) memset(obj, 0xDE, sizeof(*obj));
}



#if SIZE_MAX == UINT64_MAX
typedef struct array_buffer_t{
	char* data;
	size_t cap_exp:8, size:(sizeof(size_t)*CHAR_BIT)-8;
} array_buffer_t;
static_assert(sizeof(array_buffer_t) == sizeof(size_t) * 2);
#else
typedef struct array_buffer_t{
	char* data;
	size_t cap_exp, size;
} array_buffer_t;
static_assert(sizeof(array_buffer_t) == sizeof(size_t) * 3);
#endif
typedef struct array_iterator_t{
	char *head; size_t remaining;
} array_iterator_t;

templated size_t array_buffer_size(array_buffer_t* obj){ return obj->size; }
templated void* array_buffer_data(array_buffer_t* obj){ return obj->cap_exp?obj->data:(char*)&obj->data; }

noinline char* _array_buffer_grow(array_buffer_t* obj, char* dat, size_t* cap, size_t used2){
	char* dat2 = (char*) malloc(*cap = 1ull<<(int)(obj->cap_exp = size_magn((used2-1)|31)));
	if unlikely(!dat2) abort();
	memcpy(dat2, dat, obj->size);
	if(dat!=(char*)&obj->data) free(dat);
	obj->data = dat2;
	return dat2;
}

templated void* array_buffer_push_garbage(array_buffer_t* obj, size_t sz){
	size_t cap = obj->cap_exp; char* dat;
	if(!cap) cap = sizeof(char*), dat = (char*)&obj->data;
	else cap = 1ull<<(int)cap, dat = obj->data;
	size_t size = obj->size, used2 = size+sz;
	if(used2 > cap)
		dat = _array_buffer_grow(obj, dat, &cap, used2);
	obj->size = used2;
	return dat+size;
}

templated void array_buffer_push(array_buffer_t* obj, void* d, size_t sz){
	size_t cap = obj->cap_exp; char* dat;
	if(!cap) cap = sizeof(char*), dat = (char*)&obj->data;
	else cap = 1ull<<(int)cap, dat = obj->data;
	size_t size = obj->size, len2 = size+sz;
	if(len2 > cap)
		dat = _array_buffer_grow(obj, dat, &cap, len2);
	obj->size = len2;
	memcpy(dat+size, d, sz);
}

templated void array_buffer_push_memset(array_buffer_t* obj, int v, size_t sz){
	size_t cap = obj->cap_exp; char* dat;
	if(!cap) cap = sizeof(char*), dat = (char*)&obj->data;
	else cap = 1ull<<(int)cap, dat = obj->data;
	size_t size = obj->size, len2 = size+sz;
	if(len2 > cap)
		dat = _array_buffer_grow(obj, dat, &cap, len2);
	obj->size = len2;
	memset(dat+size, v, sz);
}

noinline void _array_buffer_shrink(array_buffer_t* obj){
	char* dat2; size_t used2 = obj->size;
	char* dat = obj->data;
	if(used2 <= sizeof(char*)){
		obj->cap_exp = 0;
		dat2 = (char*)&obj->data;
	}else{
		dat2 = obj->data = (char*) malloc(1ull<<(int)(obj->cap_exp = size_magn((used2-1)|31)));
		if unlikely(!dat2) abort();
	}
	memcpy(dat2, dat, used2);
	free(dat);
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
	memcpy(d, (obj->cap_exp ? obj->data : (char*)&obj->data)+i, sz);
}

templated void array_buffer_set(array_buffer_t* obj, size_t i, void* d, size_t sz){
	memcpy((obj->cap_exp ? obj->data : (char*)&obj->data)+i, d, sz);
}

static inline array_iterator_t array_buffer_iterator(array_buffer_t* obj, size_t i, size_t count){
	if(count > obj->size-i) count = obj->size-i;
	return (array_iterator_t){(obj->cap_exp ? obj->data : (char*)&obj->data)+i, count};
}

templated size_t array_iterator_next(array_iterator_t* obj, void* d, size_t sz){
	char *head = obj->head;
	memcpy(d, head, sz);
	obj->head = head+sz;
	return obj->remaining -= sz;
}

templated void array_buffer_clear(array_buffer_t* obj){
	if(obj->cap_exp) free(obj->data), obj->cap_exp = 0;
	obj->size = 0;
}
templated void array_buffer_destroy(array_buffer_t* obj){
	if(obj->cap_exp) free(obj->data);
	if(DEBUG) memset(obj, 0xDE, sizeof(*obj));
}

// A shared mutex. Any amount of threads may shared-acquire, only one thread at a time can exclusive-acquire, and not while any thread has the shared lock acquired. This is useful for many-readers-few-writers scenarios, where an exclusive mutex for read-only operations is excessive
typedef struct{
	// `s` is the shared lock flag, it starts at LOCK_MAX (lock_t is semaphore-style, acquire = decrement)
	// `x` is the exclusive lock flag. It itself does not protect anything except the shared lock flag
	// This is because multiple threads trying to acquire LOCK_MAX on `s` can cause deadlocks
	// Also shared locks can check/wait on the value of `x` before entering, this makes exclusive acquires faster and fairer
	// `x` needs to be ordered with respect to `s` but not with respect to what the whole lock is protecting
	alignas(sizeof(lock_t)*2) lock_t s; lock_t x;
} shared_lock_t;
static_assert(sizeof(shared_lock_t) <= CACHE_LINE); // if this was false that would be pretty insane

templated void shared_lock_init(shared_lock_t* s){
	// lock_t is semaphore style, we specify how many slots we have
	atomic_init(&s->s, LOCK_MAX);
	atomic_init(&s->x, 1);
}
// Acquire the "shared" part of a shared lock. This will block if any thread is trying to or has already obtained an exclusive lock. This will also cause all future exclusive lock acquires to block until the shared lock is released
templated void shared_lock_acquire(shared_lock_t* s){
	lock_wait(&s->x, 1);
	lock_acquire(&s->s, 1);
}
// Wait for the "shared" part of a shared lock to become available, if it isn't. This will block if any thread is trying to or has already obtained an exclusive lock. No lock is acquired, another thread may immediately acquire the lock while this function returns, you should not call `shared_lock_release` after this.
templated void shared_lock_wait(shared_lock_t* s){
	lock_wait(&s->x, 1);
	lock_wait(&s->s, 1);
}
// Try to acquire the "shared" part of a shared lock. This will return false if any thread is trying to or has already obtained an exclusive lock. See `shared_lock_acquire`
templated bool shared_lock_try_acquire(shared_lock_t* s){
	if(!lock_fetch_explicit(&s->x, memory_order_acquire)) return false;
	return lock_try_acquire(&s->s, 1);
}
// Release the "shared" part of a shared lock. Releasing more times than was acquired (i.e, calling this function when no shared part is currently acquired) is UB
templated void shared_lock_release(shared_lock_t* s){
	assert(lock_fetch(&s->s) < LOCK_MAX, "shared_lock_release() called on shared_lock_t with no shared part acquired");
	lock_release(&s->s, 1);
}
// Upgrade a "shared" lock to an exclusive one. This operation may be performed without ever releasing the shared part of the lock, in which case it will return `true`. Note that this cannot be guaranteed due to the possibility of deadlocks. This function avoids deadlocks by briefly dropping the shared part if necessary, in which case it will return `false`. In all cases, upgrading when no shared part was acquired to begin with is UB
templated bool shared_lock_upgrade(shared_lock_t* s){
	assert(lock_fetch(&s->s) < LOCK_MAX, "shared_lock_upgrade() called on shared_lock_t with no shared part acquired");
	bool f = true;
	if(!lock_try_acquire(&s->x, 1)){
		lock_release(&s->s, 1);
		// Compiler reordering above and below operation could be a deadlock.
		// If CPU reorders these, it is guaranteed to commit the release in bounded time, so the "deadlock" only lasts until then
		static_memory_barrier(mb_write_any);
		lock_acquire(&s->x, 1);
		f = false;
	}
	lock_acquire(&s->s, LOCK_MAX-f);
	return f;
}
// Try to upgrade a "shared" lock to an exclusive one. This operation is performed without ever releasing the shared part of the lock, in which case it will return `true`. If another thread owns the exclusive lock, there is a possibility of deadlocks, and the function will return false (it follows that this function cannot block on the exclusive lock, however it can block if other threads hold the shared part of the lock). In all cases, upgrading when no shared part was acquired to begin with is UB
templated bool shared_lock_try_upgrade(shared_lock_t* s){
	assert(lock_fetch(&s->s) < LOCK_MAX, "shared_lock_upgrade() called on shared_lock_t with no shared part acquired");
	if(!lock_try_acquire(&s->x, 1)) return false;
	lock_acquire(&s->s, LOCK_MAX-1);
	return true;
}
// Acquire the "exclusive" part of a shared lock. This will block if any thread is trying to or has already obtained an exclusive lock. This will also cause all future shared/exclusive lock acquires to block until the exclusive lock is released
templated void exclusive_lock_acquire(shared_lock_t* s){
	lock_acquire(&s->x, 1);
	lock_acquire(&s->s, LOCK_MAX);
}
// Wait for the "exclusive" part of a shared lock to become available. This will block if any thread is trying to or has already obtained an exclusive lock. No lock is acquired, another thread may immediately acquire the lock while this function returns, you should not call `exclusive_lock_release` after this.
templated void exclusive_lock_wait(shared_lock_t* s){
	lock_acquire(&s->x, 1);
	lock_wait(&s->s, LOCK_MAX);
	lock_release_explicit(&s->x, 1, memory_order_relaxed);
}
// Try to acquire the "exclusive" part of a shared lock. This will return false if any thread is trying to or has already obtained an exclusive lock. See `exclusive_lock_acquire`
templated bool exclusive_lock_try_acquire(shared_lock_t* s){
	if(!lock_try_acquire(&s->x, 1)) return false;
	if(!lock_try_acquire(&s->s, LOCK_MAX)){
		lock_release_explicit(&s->x, 1, memory_order_relaxed);
		return false;
	}
	return true;
}
// Release the "exclusive" part of a shared lock. Releasing when no exclusive part was acquired is UB
templated void exclusive_lock_release(shared_lock_t* s){
	assert(!lock_fetch(&s->x), "exclusive_lock_release() called on shared_lock_t with no exclusive part acquired");
	lock_release(&s->s, LOCK_MAX);
	lock_release(&s->x, 1);
}
// Downgrade from an "exclusive" lock to a shared lock, without releasing the shared part. Unlike `shared_lock_upgrade`, this does not have the same deadlock danger, and will therefore always succeed. Downgrading when no exclusive part was acquired is UB
templated void exclusive_lock_downgrade(shared_lock_t* s){
	assert(!lock_fetch(&s->x), "exclusive_lock_downgrade() called on shared_lock_t with no exclusive part acquired");
	lock_release(&s->s, LOCK_MAX-1);
	lock_release(&s->x, 1);
}