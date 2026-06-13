/**
 * Atomics & threads complement library
 * Matthew Reiner, 2026
 * Available under the GPL 3.0 license
 * Targeting: Windows, Linux, *BSD, MacOS
 * Implements the following:
 *  - Wait/Notify functionality for simple types up to 64 bit
 *  - Arbitrary condition wait
 *  - Fine-grained memory ordering
 *  - Thread management
 *  - Relax, yield & sleep
 *  - Getting the current time
 *  - Simple semaphore primitive lock_t
 */

#pragma once
#ifndef _DEFAULT_SOURCE
	#define _DEFAULT_SOURCE
#endif
#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdalign.h>
#ifdef __APPLE__
	#include <libkern/OSByteOrder.h>
	#include <machine/endian.h>
	#define bswap_16(x) OSSwapInt16(x)
	#define bswap_32(x) OSSwapInt32(x)
	#define bswap_64(x) OSSwapInt64(x)
	#define htole16(x) OSSwapHostToLittleInt16(x)
	#define htole32(x) OSSwapHostToLittleInt32(x)
	#define htole64(x) OSSwapHostToLittleInt64(x)
	#define le16toh(x) OSSwapLittleToHostInt16(x)
	#define le32toh(x) OSSwapLittleToHostInt32(x)
	#define le64toh(x) OSSwapLittleToHostInt64(x)
	#define htobe16(x) OSSwapHostToBigInt16(x)
	#define htobe32(x) OSSwapHostToBigInt32(x)
	#define htobe64(x) OSSwapHostToBigInt64(x)
	#define be16toh(x) OSSwapBigToHostInt16(x)
	#define be32toh(x) OSSwapBigToHostInt32(x)
	#define be64toh(x) OSSwapBigToHostInt64(x)
#elif defined(_MSC_VER) || defined(__OpenBSD__)
#if defined(_MSC_VER)
	#include <stdlib.h>
	#define bswap_16(x) _byteswap_ushort(x)
	#define bswap_32(x) _byteswap_ulong(x)
	#define bswap_64(x) _byteswap_uint64(x)
#else
	#include <sys/types.h>
	#include <sys/endian.h>
	#define bswap_16(x) swap16(x)
	#define bswap_32(x) swap32(x)
	#define bswap_64(x) swap64(x)
#endif
	#if defined(_MSC_VER) || __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		#define htole16(x) ((uint16_t)(x))
		#define htole32(x) ((uint32_t)(x))
		#define htole64(x) ((uint64_t)(x))
		#define htobe16(x) bswap_16(x)
		#define htobe32(x) bswap_32(x)
		#define htobe64(x) bswap_64(x)
	#else
		#define htole16(x) bswap_16(x)
		#define htole32(x) bswap_32(x)
		#define htole64(x) bswap_64(x)
		#define htobe16(x) ((uint16_t)(x))
		#define htobe32(x) ((uint32_t)(x))
		#define htobe64(x) ((uint64_t)(x))
	#endif
	#define le16toh(x) htole16(x)
	#define le32toh(x) htole32(x)
	#define le64toh(x) htole64(x)
	#define be16toh(x) htobe16(x)
	#define be32toh(x) htobe32(x)
	#define be64toh(x) htobe64(x)
#else
	#include <byteswap.h>
	#include <endian.h>
#endif

static _Atomic uint32_t _atomic_waiter_pool[32];
// `lock_t` is a simple 32-bit semaphore primitive, it can be used as a mutex, semaphore, barrier, condition variable, etc...
// It is guaranteed to be the most efficient waiting primitive on the platform. All operations best-case-scenario (i.e uncontended) are also guaranteed to be free from kernel context switch.
// This type is implemented with futexes on linux/openbsd, `_umtx` on freebsd, `ulock` on macos, `WaitOnAddress` on windows and `sched_yield` on other POSIX systems.
typedef _Atomic uint32_t lock_t;

#if !defined(alignas) && !defined(__cplusplus)
#define alignas _Alignas
#endif

#ifndef __cplusplus
// Atomic qualifier. Can be used like `atomic T` or `atomic(T)`, identically to `_Atomic`.
// Not available in C++, to avoid conflicts with std::atomic.
#define atomic _Atomic
#define thread_local _Thread_local
#endif
typedef _Atomic(uint8_t) atomic_uint8_t;
typedef _Atomic(int8_t) atomic_int8_t;
typedef _Atomic(uint16_t) atomic_uint16_t;
typedef _Atomic(int16_t) atomic_int16_t;
typedef _Atomic(uint32_t) atomic_uint32_t;
typedef _Atomic(int32_t) atomic_int32_t;
typedef _Atomic(uint64_t) atomic_uint64_t;
typedef _Atomic(int64_t) atomic_int64_t;

// Number of seconds in a microsecond (the unit used by all functions in this library). Equal to one million (1,000,000) as a type of at least 64 bits
#define SECOND_US 1000000ull
// Number of milliseconds in a microsecond (the unit used by all functions in this library). Equal to one thousand (1,000) as a type of at least 64 bits
#define MILLISECOND_US 1000ull

// Thread priority constants. See `thread_set_priority`.
typedef enum{
	// `THREAD_PRIO_BACKGROUND` is for threads performing unimportant background work. It does not have any priority, and may be starved indefinitely if the system is under heavy load.
	THREAD_PRIO_BACKGROUND,
	// `THREAD_PRIO_NORMAL` is the default priority for threads created by this library. It is suitable for most work.
	THREAD_PRIO_NORMAL,
	// `THREAD_PRIO_REALTIME` is for threads performing time-sensitive work. Using this priority for everything is not recommended as it may unnecessarily starve normal priority threads. The OS is also free to ignore the hint or kill the process if abused.
	THREAD_PRIO_REALTIME
} thread_priority_t;

#if defined(_MSC_VER)
#include <intrin.h>
#endif

// Memory barrier flags. These can be used with `thread_memory_barrier` to create custom memory barriers with specific ordering constraints, or with `static_memory_barrier` for compiler-only barriers. The `mb_acquire`, `mb_release`, `mb_acq_rel` and `mb_seq_cst` flags are provided for convenience and are equivalent to the corresponding C11 memory orders. The other flags can be used to create more fine-grained barriers.
typedef enum memory_barrier_t{
	mb_none = 0, // No ordering constraints
	mb_read_read = 1, // Order all following reads after all previous reads
	mb_read_write = 2, // Order all following writes after all previous reads
	mb_write_read = 4, // Order all following reads after all previous writes
	mb_write_write = 8, // Order all following writes after all previous writes
	mb_total_order = 16, // Force a single total order over all operations with this flag set, in addition to the specified ordering constraints
	mb_read_any = 3, // = `mb_read_read | mb_read_write`, order all following operations after all previous reads
	mb_write_any = 12, // = `mb_write_read | mb_write_write`, order all following operations after all previous writes
	mb_any_read = 5, // = `mb_read_read | mb_write_read`, order all following reads after all previous operations
	mb_any_write = 10, // = `mb_read_write | mb_write_write`, order all following writes after all previous operations
	mb_any_any = 15, // = `mb_read_read | mb_read_write | mb_write_read | mb_write_write`, order all following operations after all previous operations
	mb_relaxed = 0, // `memory_order_relaxed` is equivalent to `mb_none`. This enum exists for convenience
	mb_acquire = 3, // `memory_order_acquire` is equivalent to `mb_read_any`. This enum exists for convenience
	// mb_consume = 3,
	mb_release = 10, // `memory_order_release` is equivalent to `mb_any_write`. This enum exists for convenience
	mb_acq_rel = 11, // `memory_order_acq_rel` is equivalent to `mb_read_any | mb_any_write`. Note the absence of `mb_write_read`, which not even acq_rel provides. This enum exists for convenience
	mb_co_acquire = 12, // Acquire semantics with respect to a write instead of a read, equivalent to `mb_write_any`
	mb_co_release = 5, // Release semantics with respect to a read instead of a write, equivalent to `mb_any_read`
	mb_co_acq_rel = 13, // See `mb_co_acquire` and `mb_co_release`. Equivalent to `mb_write_any | mb_any_read`. Note the absence of `mb_read_write`. This enum exists for convenience
	mb_seq_cst = 31, // `memory_order_seq_cst` is equivalent to `mb_any_any | mb_total_order`. This enum exists for convenience
} memory_barrier_t;

// `thread_memory_barrier` is a more flexible version of `atomic_thread_fence`. It accepts any combination of the flags defined by the `memory_barrier_t` enum (OR'd together) to create a memory barrier with specific ordering constraints. The exact implementation of the barrier is platform-specific, and may be a superset of the specified constraints.
static inline void thread_memory_barrier(memory_barrier_t flags);

// Hint to relax the current thread's execution for a short period of time, to reduce contention in spin-loops. This operation is faster than yielding (see `thread_yield`) and should be preferred for short-to-medium wait durations when the system is not under load. The duration of a relaxation is hardware-specific.
static inline void thread_relax(void);

#if defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)
// Thread speculation fences are available on modern x86 CPUs using the `mfence` instruction, whose semantics were modified in light of speculative execution side-channel attacks revealed circa 2018. This macro signals the availability of the `thread_speculation_fence` function, which provides an interface to this instruction.
#define THREAD_SPECULATION_FENCE_AVAILABLE
#if defined(_MSC_VER)
static inline void thread_relax(void){ _mm_pause(); }
// See the macro `THREAD_SPECULATION_FENCE_AVAILABLE`
static inline void thread_speculation_fence(void){ _mm_lfence(); }
#else
static inline void thread_relax(void){ __builtin_ia32_pause(); }
// See the macro `THREAD_SPECULATION_FENCE_AVAILABLE`
static inline void thread_speculation_fence(void){ __builtin_ia32_lfence(); }
#endif
// In 2026 all major compilers have reasonable implementations (e.g `lock or` trick on clang or `lock inc` a temp on MSVC)
static inline void thread_memory_barrier(memory_barrier_t flags){
	if(flags&20) atomic_thread_fence(memory_order_seq_cst);
}
#elif defined(__aarch64__) || defined(__arm__) || defined(_M_ARM64) || defined(_M_ARM)
#if defined(__has_include)
#if __has_include(<arm_acle.h>)
#include <arm_acle.h>
#endif
#endif

#ifdef _MSC_VER
#include <intrin.h>
static inline void thread_relax(void){ __yield(); }
static inline void thread_memory_barrier(memory_barrier_t flags){
	if(flags&16){ atomic_thread_fence(memory_order_seq_cst); return; }
	if(flags&3){
		if(flags&12){ atomic_thread_fence(flags&4 ? memory_order_seq_cst : flags&1 ? memory_order_acq_rel : memory_order_release); return; }
		atomic_thread_fence(memory_order_acquire);
	}else if(flags&4){
		__dmb(_ARM64_BARRIER_ISHST);
		_ReadWriteBarrier();
	}else if(flags&8){
		__dmb(_ARM64_BARRIER_ISHST);
		atomic_signal_fence(memory_order_release);
	}
}
#else
static inline void thread_relax(void){  __asm__ __volatile__("yield"); }

static inline void thread_memory_barrier(memory_barrier_t flags){
	if(flags&16){ atomic_thread_fence(memory_order_seq_cst); return; }
	if(flags&3){
		if(flags&12){ atomic_thread_fence(flags&4 ? memory_order_seq_cst : flags&1 ? memory_order_acq_rel : memory_order_release); return; }
		atomic_thread_fence(memory_order_acquire);
#if defined(__ARM_ARCH) && __ARM_ARCH >= 7
	}else if(flags&4) __asm__ __volatile__("dmb ishst" ::: "memory");
	else if(flags&8){
		__asm__ __volatile__("dmb ishst");
		atomic_signal_fence(memory_order_release);
#else
	}else if(flags&4) atomic_thread_fence(memory_order_seq_cst);
	else if(flags&8){
		atomic_thread_fence(memory_order_release);
#endif
	}
}
#if defined(__ARM_ARCH) && __ARM_ARCH >= 8
// Thread speculation fences are available on modern ARM-based CPUs using the `csdb` instruction, which was specifically introduced in light of speculative execution side-channel attacks revealed circa 2018. This macro signals the availability of the `thread_speculation_fence` function, which provides an interface to this instruction.
#define THREAD_SPECULATION_FENCE_AVAILABLE
// See the macro `THREAD_SPECULATION_FENCE_AVAILABLE`
static inline void thread_speculation_fence(void){ __asm__ __volatile__("csdb" ::: "memory"); }
#endif
#endif

#elif defined(__riscv)
#if defined(__riscv_zihintpause)
static inline void thread_relax(void){ __asm__ __volatile__("pause"); }
#else
static inline void thread_relax(void){ __asm__ __volatile__("nop"); }
#endif
static inline void thread_memory_barrier(memory_barrier_t flags){
	switch((int)flags){
		case 0: break;
#define _A_FENCE_TYPE(n, asm) case n: __asm__ __volatile__(asm); break;
		_A_FENCE_TYPE(1, "fence r, r")
		_A_FENCE_TYPE(2, "fence r, w")
		_A_FENCE_TYPE(3, "fence r, rw")
		_A_FENCE_TYPE(4, "fence w, r")
		_A_FENCE_TYPE(5, "fence rw, r")
		_A_FENCE_TYPE(6, "fence w, r; fence r, w")
		_A_FENCE_TYPE(7, "fence w, r; fence r, rw")
		_A_FENCE_TYPE(8, "fence w, w")
		_A_FENCE_TYPE(9, "fence w, w; fence r, r")
		_A_FENCE_TYPE(10, "fence rw, w")
		_A_FENCE_TYPE(11, "fence rw, w; fence r, r")
		_A_FENCE_TYPE(12, "fence w, rw")
		_A_FENCE_TYPE(13, "fence w, rw; fence r, r")
		_A_FENCE_TYPE(14, "fence rw, w; fence w, r")
#undef _A_FENCE_TYPE
		default: __asm__ __volatile__("fence rw, rw");
	}
	atomic_signal_fence((flags&~3) == 0 ? flags ? memory_order_acquire : memory_order_relaxed : (flags&~3) == 8 ? flags&1 ? memory_order_acq_rel : memory_order_release : memory_order_seq_cst);
}
#else
static inline void thread_relax(void){ __asm__ __volatile__("nop"); }
static inline void thread_memory_barrier(memory_barrier_t flags){
	atomic_thread_fence((flags&~3) == 0 ? flags ? memory_order_acquire : memory_order_relaxed : (flags&~3) == 8 ? flags&1 ? memory_order_acq_rel : memory_order_release : memory_order_seq_cst);
}
#endif

// `thread_memory_barrier` is a more flexible version of `atomic_signal_fence`. It accepts any combination of the flags defined by the `memory_barrier_t` enum (OR'd together) to create a compiletime-only memory barrier with specific ordering constraints. The exact implementation of the barrier is platform-specific, and may be a superset of the specified constraints.
static inline void static_memory_barrier(memory_barrier_t flags){
	atomic_signal_fence(((int)flags&~3) == 0 ? flags ? memory_order_acquire : memory_order_relaxed : ((int)flags&~3) == 8 ? flags&1 ? memory_order_acq_rel : memory_order_release : memory_order_seq_cst);
}

#ifndef A_H_DEFAULT_SPIN
// Try to thread_relax() this many times while waiting on an atomic.
#define A_H_DEFAULT_SPIN 48
#endif
#ifndef A_H_DEFAULT_YIELD
// Try to thread_yield() this many times while waiting on an atomic.
#define A_H_DEFAULT_YIELD 6
#endif
// After this many spin/yield, we use a thread parking loop: SYS_futex on Linux, futex() on FreeBSD, _umtx_op on OpenBSD, SYS_ulock_* on MacOS, and WaitOnAddress/WakeByAddress* on Windows
// SYS_ulock_* is technically unstable on Mac, although unlikely to go away or change any time soon
// You can disable it with `#define APPLE_NO_UNSTABLE_ULOCK` before including this header, which will cause the implementation to fall back to the yield loop on MacOS

// Yield the current thread's execution to allow other threads to run. This operation is slower than relaxing (see `thread_relax`) and should be preferred for long wait durations or when the system is under load.
static inline void thread_yield(void);

#define _atomic_futex_loop(addr, val, wait, s, y, o) int count = s; \
	while(count--) if(atomic_load_explicit(addr, o) != val) return; else thread_relax(); \
	count = y; while(count--) if(atomic_load_explicit(addr, o) != val) return; else thread_yield(); \
	wait; goto check;

// Returns the a hint for the maximum available concurrency on this system. Assigning busy work to more threads than this is more likely to be detrimental to performance than beneficial.
static inline size_t available_concurrency(void);
// Sleep for the given number of microseconds. Note that the actual sleep duration may be longer than the requested duration, especially if the system is under load or if the requested duration is very short (e.g. less than 1 millisecond).
static inline void thread_sleep(uint64_t useconds);
// Set the current thread's priority. See the `thread_priority_t` enum for possible values. Returns `true` on success, `false` on failure (e.g. if the OS does not support thread priorities or if the calling thread does not have permission to set its own priority).
static inline bool thread_set_priority(thread_priority_t p);

// Monotonic time in microseconds. This clock is guaranteed to be steady (i.e. it will never go backwards) and is not affected by changes to the system time. This clock is not guaranteed to be the "truth", it may drift relative to other physical machines. (time measurement is not objective and inherently imprecise due to a multitude of physics constraints)
static inline uint64_t mono_now(void);

// Time in microseconds since Jan 1st 1970 ("UNIX timestamp"). This clock is not guaranteed to be steady (i.e. it may jump backwards/forwards due to changes to the system time. This clock is not guaranteed to be the "truth", it may naturally drift relative to other physical machines. (time measurement is not objective and inherently imprecise due to a multitude of physics constraints)
static inline uint64_t epoch_now(void);

// Time in microseconds that the current thread has been running. This clock is guaranteed to be steady (i.e. it will never go backwards), but not guaranteed to start from `0` at thread creation. This clock does not go up while the current thread is blocking, preempted, or the system is in sleep, it is mainly used to measure CPU usage by comparing values taken at different times.
static inline uint64_t thread_now(void);

#ifdef _WIN32
	// Opaque thread handle type. This value is guaranteed to not be zero for any valid thread, and can be equality-tested using `==` as normal.
	// The windows implementation performs a small amount of additional bookkeeping as Windows APIs differ substantially from POSIX and from what this library guarantees.
	typedef struct _thread_t* thread_t;
	typedef uintptr_t wait_t;
#else
	#include <pthread.h>
	// Opaque thread handle type. This value is guaranteed to not be zero for any valid thread, and can be equality-tested using `==` as normal.
	typedef pthread_t thread_t;
	#if defined(__NetBSD__) || defined(__sun)
		#ifdef __sun
			#include <sys/lwp.h>
			#include <thread.h>
		#else
			#include <lwp.h>
		#endif
	typedef lwpid_t wait_t;
	#else
	typedef uintptr_t wait_t;
	#endif
#endif

// Create a new thread that starts executing the given function with the given argument. The `stack` parameter specifies the desired stack size for the new thread, or `0` to use the system default. Returns a handle to the new thread, or `(thread_t)0` on failure.
static inline thread_t thread_create(void* (*fn)(void*), void* arg, size_t stack);

// Wait for the given thread to finish executing and return the value returned by the thread's function. The thread's resources and handle are automatically freed by this function, and must not be used after calling this function. It is undefined behavior to call this function more than once on the same thread, or on a thread that has been detached (see `thread_detach`).
static inline void* thread_join(thread_t t);
// Mark a thread as detached. The OS will not wait for the thread's function to return when the main thread exits. The thread's resources are also freed immediately when it returns, and not when `thread_join` is called. It is undefined behavior to call this function more than once on the same thread, or on a thread that is already being waited on (see `thread_join`).
static inline void thread_detach(thread_t t);

// Return a handle to the current thread. The returned value is guaranteed to compare `==` to the value returned by `thread_create` for that thread.
// When this function is called from a thread that was not created by `thread_create` (e.g. the main thread or a thread created by another library), it will compare `!=` to all valid thread handles returned by `thread_create`, and `!=` to `(thread_t)0`, but is otherwise unspecified (e.g. it may return a unique value for each thread, or the same value for all threads).
static inline thread_t thread_self(void);

// Get a wait token used by `thread_wait` and `thread_wake`
static inline wait_t thread_wait_token();
// Pause execution of the current thread until any thread calls `thread_wake()` on the same token. The token passed to this function must have been obtained by `thread_wait_token()` on the same thread. If `thread_wake()` is called before this function is called, then it will return immediately.
static inline void thread_wait(wait_t token);
// Resume the execution of another thread from a wait token (see `thread_wait()`). The token passed to this function must have been obtained by `thread_wait_token()` on the thread to resume. Calling `thread_wake()` multiple times for one wait token is undefined behavior.
static inline void thread_wake(wait_t token);

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#undef NOMINMAX
// Top tier windows trolling
#undef near
#undef far
#undef pascal
#undef cdecl


typedef SSIZE_T ssize_t;

static inline void _atomic_wait8(void* addr, uint8_t val){ WaitOnAddress(addr, &val, 1, INFINITE); }
static inline void _atomic_wait16(_Atomic uint16_t* addr, uint16_t val){ WaitOnAddress((void*) addr, &val, 2, INFINITE); }
static inline void _atomic_wait32(_Atomic uint32_t* addr, uint32_t val){ WaitOnAddress((void*) addr, &val, 4, INFINITE); }
static inline void _atomic_wait64(_Atomic uint64_t* addr, uint64_t val){ WaitOnAddress((void*) addr, &val, 8, INFINITE); }
static inline void _atomic_waitloop8(void* addr, uint8_t val, memory_order o){ _atomic_futex_loop((_Atomic uint8_t*)addr, val, check: WaitOnAddress(addr, &val, 1, INFINITE), A_H_DEFAULT_SPIN, A_H_DEFAULT_YIELD, o); }
static inline void _atomic_waitloop16(_Atomic uint16_t* addr, uint16_t val, memory_order o){ _atomic_futex_loop(addr, val, check: WaitOnAddress((void*) addr, &val, 2, INFINITE), A_H_DEFAULT_SPIN, A_H_DEFAULT_YIELD, o); }
static inline void _atomic_waitloop32(_Atomic uint32_t* addr, uint32_t val, memory_order o){ _atomic_futex_loop(addr, val, check: WaitOnAddress((void*) addr, &val, 4, INFINITE), A_H_DEFAULT_SPIN, A_H_DEFAULT_YIELD, o); }
static inline void _atomic_waitloop64(_Atomic uint64_t* addr, uint64_t val, memory_order o){ _atomic_futex_loop(addr, val, check: WaitOnAddress((void*) addr, &val, 8, INFINITE), A_H_DEFAULT_SPIN, A_H_DEFAULT_YIELD, o); }

static inline void _atomic_wait_ptr(void* a_, void* b_){ WaitOnAddress(a_, &b_, sizeof(void*), INFINITE); }
static inline void _atomic_waitloop_ptr(void* a_, void* b_, memory_order o){ _Atomic uintptr_t* addr = (_Atomic uintptr_t*)a_; uintptr_t val = (uintptr_t)b_; _atomic_futex_loop(addr, val, check: WaitOnAddress((void*) addr, &val, sizeof(uintptr_t), INFINITE), A_H_DEFAULT_SPIN, A_H_DEFAULT_YIELD, o); }

// Notify an `atomic_wait` that the value may have changed
// This will wake one or more threads waiting on the given address. `n` is the number of threads to wake, or `-1` to wake all threads. The implementation may wake more threads than requested, but will never wake fewer threads than requested or are waiting.
// On Windows, the implementation will wake all threads when `n > 1` (this is an implementation constraint).
#define atomic_wake(ptr, n) do{ if((int)(n)==1) WakeByAddressSingle(ptr); else WakeByAddressAll(ptr); }while(0)

#define _atomic_wake32_all(ptr) WakeByAddressAll(ptr)

static inline void _atomic_wake_condition(void* addr, int n){
	_Atomic uint32_t *fut = &_atomic_waiter_pool[(((uintptr_t)addr)^((uintptr_t)addr>>5))&31];
	atomic_fetch_add_explicit(fut, 1, memory_order_release);
	atomic_wake(addr, n);
}

struct _thread_t{
	void* (*fn)(void*);
	void* arg;
	_Atomic HANDLE _handle;
};

static inline size_t available_concurrency(void){ DWORD n = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS); return n <= 0 ? 1 : n; }

static _Thread_local thread_t _a_thread_self = (thread_t)-1;
static _Thread_local uint8_t _a_park_flag = 0;

static inline DWORD WINAPI _thread_wrapper(void* a_){
	struct _thread_t* a = _a_thread_self = (struct _thread_t*)a_;
	a->arg = a->fn(a->arg);
	HANDLE h = atomic_exchange_explicit(&a->_handle, 0, memory_order_release);
	if(h) CloseHandle(h);
	else free(a);
	return 0;
}

static inline thread_t thread_create(void* (*fn)(void*), void* arg, size_t stack){
	HANDLE h;
	struct _thread_t* t = (struct _thread_t*) malloc(sizeof(struct _thread_t));
	t->fn = fn;
	t->arg = arg;
	atomic_thread_fence(memory_order_release);
	t->_handle = CreateThread(NULL, stack, _thread_wrapper, t, 0, NULL);
	if(t->_handle == INVALID_HANDLE_VALUE){ free(t); return 0; }
	return t;
}

static inline void* thread_join(thread_t t){
	HANDLE h = atomic_load_explicit(&t->_handle, memory_order_acquire);
	if(h){
		WaitForSingleObject(h, INFINITE);
		CloseHandle(h);
	}
	void* ret = t->arg;
	free(t);
	return ret;
}
static inline void thread_detach(thread_t t){
	HANDLE h = atomic_exchange_explicit(&t->_handle, 0, memory_order_relaxed);
	if(h){ CloseHandle(h); }
	else free(t);
}

static inline thread_t thread_self(void){ return _a_thread_self; }
static inline void thread_yield(void){ SwitchToThread(); }
#define _SLEEP_MAX (uint64_t)(INFINITE-1)
static inline void thread_sleep(uint64_t useconds){
	useconds = (useconds+999) / 1000;
	// useconds becomes milliseconds
	while(useconds > _SLEEP_MAX){
		useconds -= _SLEEP_MAX;
		Sleep(_SLEEP_MAX);
	}
	Sleep((DWORD) useconds);
}

static inline bool thread_set_priority(thread_priority_t p){
	return SetThreadPriority(GetCurrentThread(), p == THREAD_PRIO_BACKGROUND ? THREAD_PRIORITY_LOWEST : p == THREAD_PRIO_REALTIME ? THREAD_PRIORITY_TIME_CRITICAL : THREAD_PRIORITY_NORMAL);
}

static inline wait_t thread_wait_token(){
	return (uintptr_t)&_a_park_flag;
}
static inline void thread_wait(wait_t v){
	uint8_t zero = 0;
	WaitOnAddress((uint8_t*)v, &zero, 1, INFINITE);
	*(uint8_t*)v = 0;
}
static inline void thread_wake(wait_t v){
	*(uint8_t*)v = 1;
	WakeByAddressSingle((uint8_t*)v);
}

static inline uint64_t mono_now(void){
	static double pfreq = -1;
	LARGE_INTEGER counter;
	QueryPerformanceCounter(&counter);
	if(pfreq < 0){
		LARGE_INTEGER f;
		QueryPerformanceFrequency(&f);
		pfreq = (double)SECOND_US / (double)f.QuadPart;
	}
	return (uint64_t)(counter.QuadPart * pfreq);
}

static inline uint64_t epoch_now(void){
	FILETIME ft;
	ULARGE_INTEGER uli;
	GetSystemTimePreciseAsFileTime(&ft);
	uli.LowPart = ft.dwLowDateTime;
	uli.HighPart = ft.dwHighDateTime;
	return uli.QuadPart/10 - 11644473600000000LL;
}

static inline uint64_t thread_now(void){
	FILETIME kernel, user;
	if(!GetThreadTimes(GetCurrentThread(), 0, 0, &kernel, &user)) return 0;
	uint64_t k =
		((uint64_t)kernel.dwHighDateTime << 32) |
		kernel.dwLowDateTime;
	uint64_t u =
		((uint64_t)user.dwHighDateTime << 32) |
		user.dwLowDateTime;
	return (k+u)/10;
}

#else
#include <sched.h>
#include <unistd.h>
#ifdef __linux__
#include <linux/futex.h>
#elif defined(__OpenBSD__)
#include <sys/time.h>
#include <sys/futex.h>
#elif defined(__FreeBSD__)
#include <sys/umtx.h>
#endif
#include <sys/syscall.h>
#include <limits.h>
#include <errno.h>
#include <time.h>

#ifdef __linux__

// Note on _atomic_futex_small:
// Every 8 bit value is inside some aligned 32 bit value that doesn't cross a page boundary, same for 16 bit
// C standard might say loading this 32 bit value is UB and to that I say BITE ME
// We use volatile here to break the compiler's assumptions about memory
// This does not "fix" the UB, but does make the UB mostly non-actionable to the compiler in practice
// If you sacrifice performance for "idiomatic correctness" you are a sucker and PRs as such will not be accepted
// We use bitset to guarantee that wake ops will wakes the correct thread, even if multiple threads are waiting
//   on the same 32 bit word but different 8/16 bit portions of that word

// _atomic_futex32 is just normal futexes
// _atomic_futex64 has to be emulated via a waiter pool: each "waiter" tracks the wake "generation" to avoid lost wakes between the check and the actual syscall
//   (this only breaks if there have been exactly 2^32 wakes between the check and the syscall which is virtually impossible in practice)
// _atomic_futex64 also makes use of bitset to reduce unnecessary wakeups (from 1-in-32 to 1-in-1024)
// The exact same algorithm used by _atomic_futex64 can be used to implement wait for arbitrary sizes or conditions

#define _atomic_futex_wake_small(addr, n) int off = ((uintptr_t)addr)&3; \
	syscall(SYS_futex, (char*)addr-off, FUTEX_WAKE_BITSET_PRIVATE, n, 0, 0, 1<<(off<<3))
#define _atomic_futex_wake32(addr, n) syscall(SYS_futex, addr, FUTEX_WAKE_PRIVATE, n, 0, 0)
#define _atomic_futex_wake64(addr, n) _Atomic uint32_t *fut = &_atomic_waiter_pool[((uintptr_t)addr>>3)&31]; \
	atomic_fetch_add_explicit(fut, 1, memory_order_release); \
	syscall(SYS_futex, fut, FUTEX_WAKE_BITSET_PRIVATE, n, 0, 0, 1u<<(((uintptr_t)addr>>8)&31));
#define _atomic_futex_small(addr, val, m, check) int off = ((uintptr_t)addr)&3; \
	void* addr2 = (char*)addr-off; off <<= 3; \
	check {\
	uint32_t v = atomic_load_explicit((volatile _Atomic uint32_t*) addr2, memory_order_relaxed); \
	uint32_t v2 = v&m | val<<off; \
	if(v != v2) return; \
	syscall(SYS_futex, addr2, FUTEX_WAIT_BITSET_PRIVATE, v, 0, 0, 1<<off); }
#define _atomic_futex32(addr, val) syscall(SYS_futex, addr, FUTEX_WAIT_PRIVATE, val, 0, 0)
#define _atomic_futex64(addr, val, check) _Atomic uint32_t *fut = &_atomic_waiter_pool[((uintptr_t)addr>>3)&31]; \
	uint32_t tok = atomic_load_explicit(fut, memory_order_acquire); \
	if(atomic_load_explicit(addr, memory_order_relaxed) != val) return; \
	uint32_t m = 1u<<(((uintptr_t)addr>>8)&31); \
	check { \
	syscall(SYS_futex, fut, FUTEX_WAIT_BITSET_PRIVATE, tok, 0, 0, m); \
	if(atomic_load_explicit(addr, memory_order_relaxed) != val) return; \
	uint32_t tok2 = tok; if(tok2 == (tok=atomic_load_explicit(fut, memory_order_relaxed))) return; \
	syscall(SYS_futex, fut, FUTEX_WAKE_BITSET_PRIVATE, INT_MAX, 0, 0, m); }

#elif defined(__OpenBSD__)

#define _atomic_futex32(addr, val) \
	futex((volatile uint32_t*)(addr), FUTEX_WAIT, (int)(val), NULL, NULL)

#define _atomic_futex_wake32(addr, n) \
	futex((volatile uint32_t*)(addr), FUTEX_WAKE, (int)(n), NULL, NULL)

#elif defined(__FreeBSD__)

#define _atomic_futex32(addr, val) \
	_umtx_op(addr, UMTX_OP_WAIT_UINT_PRIVATE, val, 0, 0)

#define _atomic_futex_wake32(addr, n) \
	_umtx_op(addr, UMTX_OP_WAKE_PRIVATE, n, 0, 0)

#elif defined(__APPLE__) && !defined(APPLE_NO_UNSTABLE_ULOCK)

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#define _atomic_futex32(addr, val) \
	syscall(SYS_ulock_wait, 0x1000001, addr, val, 0)

#define _atomic_futex_wake32(addr, n) \
	syscall(SYS_ulock_wake, 0x1000001, addr, n)

#else

// Fallback
#warning "No futex-like primitive found (falling back to yield-loop)"
#define _A_FUTEX_FALLBACK
#define _atomic_futex32(addr, val) sched_yield()
#define _atomic_futex_wake32(addr, n) {}

#endif

// MacOS __ulock and BSD _umtx are pretty similar
// Generic 32 bit futex, because the rest is so similar
// Read the notes on the linux implementation
// Main difference: we don't have bitset, so _atomic_futex_small needs the same "wake the others" condition as _atomic_futex64
// Additionally, _atomic_futex64 can't use the mask for additional waiter pool separation, so we compensate by using a better hash instead

#ifdef _A_FUTEX_FALLBACK

#define _atomic_futex_small(addr, val, m, check) sched_yield()
#define _atomic_futex_wake_small(addr, n) {}
#define _atomic_futex64(addr, val, _) sched_yield()
#define _atomic_futex_wake64(addr, n) {}

#elif !defined(__linux__)

	#define _atomic_futex_wake_small(addr, n) int off = ((uintptr_t)addr)&3; \
		_atomic_futex_wake32((char*)addr-off, n)
	#define _atomic_futex_small(addr, val, m, check) int off = ((uintptr_t)addr)&3; \
		volatile _Atomic uint32_t* addr2 = (volatile _Atomic uint32_t*)((char*)addr-off); off <<= 3; \
		check {\
		uint32_t v = atomic_load_explicit(addr2, memory_order_relaxed); \
		uint32_t v2 = v&m | (uint32_t)(val)<<off; \
		if(v != v2) return; \
		_atomic_futex32(addr2, v); \
		uint32_t v3 = atomic_load_explicit(addr2, memory_order_relaxed)^v; \
		if(v3&m) return; \
		if(v3^~m) _atomic_futex_wake32(addr2, INT_MAX);}

	#if ULONG_MAX == UINT64_MAX && defined(__FreeBSD__)
		#define _atomic_futex_wake64(addr, n) _umtx_op(addr, UMTX_OP_WAKE_PRIVATE, n, 0, 0)
		#define _atomic_futex64(addr, val, _) _umtx_op(addr, UMTX_OP_WAIT_PRIVATE, val, 0, 0)
	#else
		#define _atomic_futex_wake64(addr, n) _Atomic uint32_t *fut = &_atomic_waiter_pool[(((uintptr_t)addr>>3)^((uintptr_t)addr>>8))&31]; \
			atomic_fetch_add_explicit(fut, 1, memory_order_release); \
			_atomic_futex_wake32(fut, n)
		#define _atomic_futex64(addr, val, check) _Atomic uint32_t *fut = &_atomic_waiter_pool[(((uintptr_t)addr>>3)^((uintptr_t)addr>>8))&31]; \
			uint32_t tok = atomic_load_explicit(fut, memory_order_acquire); \
			if(atomic_load_explicit(addr, memory_order_relaxed) != val) return; \
			check { \
			_atomic_futex32(fut, tok); \
			if(atomic_load_explicit(addr, memory_order_relaxed) != val) return; \
			uint32_t tok2 = tok; if(tok2 == (tok=atomic_load_explicit(fut, /*this is okay: order between this and previous load doesn't matter, and the _atomic_futex_wake32 below provides us with acquire semantics*/ memory_order_relaxed))) return; \
			_atomic_futex_wake32(fut, INT_MAX); }
	#endif

#endif
static inline void _atomic_wait8(void* addr, uint8_t val){ _atomic_futex_small(addr, val, ~(255u<<off), ) }
static inline void _atomic_wait16(_Atomic uint16_t* addr, uint16_t val){ _atomic_futex_small(addr, val, (0xFFFF0000u>>off), ) }
static inline void _atomic_wait32(_Atomic uint32_t* addr, uint32_t val){ _atomic_futex32(addr, val); }
static inline void _atomic_wait64(_Atomic uint64_t* addr, uint64_t val){ _atomic_futex64(addr, val, ) }
static inline void _atomic_waitloop8(void* addr, uint8_t val, memory_order o){ _atomic_futex_loop((_Atomic uint8_t*)addr, val, _atomic_futex_small(addr, val, ~(255u<<off), check:), A_H_DEFAULT_SPIN, A_H_DEFAULT_YIELD, o) }
static inline void _atomic_waitloop16(_Atomic uint16_t* addr, uint16_t val, memory_order o){ _atomic_futex_loop(addr, val, _atomic_futex_small(addr, val, (0xFFFF0000u>>off), check:), A_H_DEFAULT_SPIN, A_H_DEFAULT_YIELD, o) }
static inline void _atomic_waitloop32(_Atomic uint32_t* addr, uint32_t val, memory_order o){ _atomic_futex_loop(addr, val, check: _atomic_futex32(addr, val), A_H_DEFAULT_SPIN, A_H_DEFAULT_YIELD, o) }
static inline void _atomic_waitloop64(_Atomic uint64_t* addr, uint64_t val, memory_order o){ _atomic_futex_loop(addr, val, _atomic_futex64(addr, val, check:), A_H_DEFAULT_SPIN, A_H_DEFAULT_YIELD, o) }

static inline void _atomic_wake8_16(void* addr, int n){ _atomic_futex_wake_small(addr, n); }
static inline void _atomic_wake32(void* addr, int n){ _atomic_futex_wake32(addr, n); }
static inline void _atomic_wake64(void* addr, int n){ _atomic_futex_wake64(addr, n); }

#if UINTPTR_MAX == UINT64_MAX
static inline void _atomic_wait_ptr(void* a_, void* b_){ _Atomic uint64_t* addr = (_Atomic uint64_t*)a_; uint64_t val = (uint64_t)b_; _atomic_futex64(addr, val, ) }
static inline void _atomic_waitloop_ptr(void* a_, void* b_, memory_order o){ _Atomic uint64_t* addr = (_Atomic uint64_t*)a_; uint64_t val = (uint64_t)b_; _atomic_futex_loop(addr, val, _atomic_futex64(addr, val, check:), A_H_DEFAULT_SPIN, A_H_DEFAULT_YIELD, o) }
#define _atomic_wake_arch _atomic_wake64
#else
static inline void _atomic_wait_ptr(void* a_, void* b_){ _atomic_futex32(((_Atomic uint32_t*)a_), ((uint32_t)b_)); }
static inline void _atomic_waitloop_ptr(void* a_, void* b_, memory_order o){ _Atomic uint32_t* addr = a_; uint32_t val = (uint32_t)b_; _atomic_futex_loop(addr, val, check: _atomic_futex32(addr, val), A_H_DEFAULT_SPIN, A_H_DEFAULT_YIELD, o) }
#define _atomic_wake_arch _atomic_wake32
#endif

// Notify an `atomic_wait` that the value may have changed
// This will wake one or more threads waiting on the given address. `n` is the number of threads to wake, or `-1` to wake all threads. The implementation may wake more threads than requested, but will never wake fewer threads than requested or are waiting.
#define atomic_wake(ptr, n) _Generic((ptr), \
	_Atomic(_Bool)*: _atomic_wake8_16, _Atomic(uint8_t)*: _atomic_wake8_16, _Atomic(int8_t)*: _atomic_wake8_16, \
	_Atomic(uint16_t)*: _atomic_wake8_16, _Atomic(int16_t)*: _atomic_wake8_16, \
	_Atomic(uint32_t)*: _atomic_wake32, _Atomic(int32_t)*: _atomic_wake32, \
	_Atomic(uint64_t)*: _atomic_wake64, _Atomic(int64_t)*: _atomic_wake64, \
	default: _atomic_wake_arch \
)(ptr, n)

#define _atomic_wake32_all(ptr) _atomic_wake32(ptr, INT_MAX)

static inline void _atomic_wake_condition(void* addr, int n){
	_Atomic uint32_t *fut = &_atomic_waiter_pool[(((uintptr_t)addr)^((uintptr_t)addr>>5))&31];
	atomic_fetch_add_explicit(fut, 1, memory_order_release);
	_atomic_futex_wake32(fut, n);
}

static inline size_t available_concurrency(void){ long x = sysconf(_SC_NPROCESSORS_ONLN); return (size_t)(x <= 0 ? 1 : x); }

static inline thread_t thread_create(void* (*fn)(void*), void* arg, size_t stack){
	// This implementation assumes that (pthread_t)0 is never used. This is usually true in practice
#ifdef __cplusplus
	thread_t t = {};
#else
	thread_t t = {0};
#endif
	if(!stack){ pthread_create(&t, 0, fn, arg); return t; }
	pthread_attr_t a;
	pthread_attr_init(&a);
	pthread_attr_setstacksize(&a, stack);
	pthread_create(&t, &a, fn, arg);
	pthread_attr_destroy(&a);
	return t;
}

static inline void thread_detach(thread_t t){ pthread_detach(t); }
static inline void* thread_join(thread_t t){ void* res; pthread_join(t, &res); return res; }

#if defined(__NetBSD__) || defined(__sun)

static inline wait_t thread_wait_token(){ return _lwp_self(); }
static inline void thread_wait(wait_t token){
	// Useless arguments
#ifdef __sun
	_lwp_park(0, 0, 0, 0);
#else
	_lwp_park(0, 0, 0, 0, 0, 0);
#endif
}
static inline void thread_wake(wait_t token){ _lwp_unpark(token, 0); }

#else

static _Thread_local uint32_t _a_park_flag = 0;
static inline wait_t thread_wait_token(){
	return (uintptr_t)&_a_park_flag;
}
static inline void thread_wait(wait_t v){
	_atomic_futex32((uint32_t*)v, 0);
	*(uint32_t*)v = 0;
}
static inline void thread_wake(wait_t v){
	*(uint32_t*)v = 1;
	_atomic_wake32(v, 1);
}

#endif

static inline thread_t thread_self(void){ return pthread_self(); }
static inline void thread_yield(void){ sched_yield(); }

static inline void thread_sleep(uint64_t useconds){
	struct timespec ts;
	ts.tv_sec = useconds/1000000;
	ts.tv_nsec = (long)(useconds - (uint64_t)(ts.tv_sec)*1000000) * 1000;
#ifdef __linux__
	while(clock_nanosleep(CLOCK_MONOTONIC, 0, &ts, &ts) && errno == EINTR);
#else
	while(nanosleep(&ts, &ts) && errno == EINTR);
#endif
}

static inline uint64_t mono_now(void){
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)(ts.tv_nsec/1000) + SECOND_US*(uint64_t)ts.tv_sec;
}

static inline uint64_t epoch_now(void){
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return (uint64_t)(ts.tv_nsec/1000) + SECOND_US*(uint64_t)ts.tv_sec;
}

static inline bool thread_set_priority(thread_priority_t p){
	struct sched_param param = {0};
#ifdef SCHED_IDLE
	return !pthread_setschedparam(pthread_self(), p == THREAD_PRIO_REALTIME ? SCHED_RR : p == THREAD_PRIO_NORMAL ? SCHED_OTHER : SCHED_IDLE, &param);
#else
	return !pthread_setschedparam(pthread_self(), p == THREAD_PRIO_REALTIME ? SCHED_RR : SCHED_OTHER, &param);
#endif
}

static inline uint64_t thread_now(void){
	struct timespec ts;
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
	return (uint64_t)(ts.tv_nsec/1000) + SECOND_US*(uint64_t)ts.tv_sec;
}

#endif

typedef _Atomic(ssize_t) atomic_ssize_t;

#define _atomic_wait_until(key, cond, s, y) do{ \
	int _atomic_count = s; \
	while(_atomic_count--) if(cond) break; else thread_relax(); \
	_atomic_count = y; while(_atomic_count--) if(cond) break; else thread_yield(); \
	void* _atomic_addr = (void*)(key); \
	_Atomic uint32_t *_atomic_fut = &_atomic_waiter_pool[(((uintptr_t)_atomic_addr)^((uintptr_t)_atomic_addr>>5))&31]; \
	uint32_t _atomic_tok = atomic_load_explicit(_atomic_fut, memory_order_acquire); \
	if(cond) break; \
	for(;;){ \
	_atomic_wait32(_atomic_fut, _atomic_tok); \
	if(cond) break; \
	uint32_t _atomic_tok2 = _atomic_tok; if(_atomic_tok2 != (_atomic_tok=atomic_load_explicit(_atomic_fut, memory_order_relaxed))) _atomic_wake32(_atomic_fut, INT_MAX); \
	} }while(0)

// Wait on the given address until it no longer contains the given value AND another thread has notified the kernel via `atomic_wake`. The implementation may occasionally wake spuriously (i.e with no corresponding `atomic_wake`), so the condition should always be re-checked after this function returns.
#define atomic_wait(ptr, val) _Generic((ptr), \
	_Atomic(_Bool)*: _atomic_wait8, _Atomic(uint8_t)*: _atomic_wait8, _Atomic(int8_t)*: _atomic_wait8, \
	_Atomic(uint16_t)*: _atomic_wait16, _Atomic(int16_t)*: _atomic_wait16, \
	_Atomic(uint32_t)*: _atomic_wait32, _Atomic(int32_t)*: _atomic_wait32, \
	_Atomic(uint64_t)*: _atomic_wait64, _Atomic(int64_t)*: _atomic_wait64, \
	default: _atomic_wait_ptr \
)(ptr, val)
// Wait on the given address until it no longer contains the given value AND another thread has notified the kernel via `atomic_wake`. Unlike `atomic_wait`, the condition is re-checked for you to rule out spurious wakeups. Note that this operation finishing is only a guarantee that the condition was true at some point in time, for many use-cases (e.g locks), this is still not sufficient (e.g two threads may be woken but only one can acquire the lock, so the other thread will have to go back to sleep), in such cases it is better to use `atomic_wait` rather than cause unnecessary nested loops.
#define atomic_wait_loop(ptr, val, o) _Generic((ptr), \
	_Atomic(_Bool)*: _atomic_waitloop8, _Atomic(uint8_t)*: _atomic_waitloop8, _Atomic(int8_t)*: _atomic_waitloop8, \
	_Atomic(uint16_t)*: _atomic_waitloop16, _Atomic(int16_t)*: _atomic_waitloop16, \
	_Atomic(uint32_t)*: _atomic_waitloop32, _Atomic(int32_t)*: _atomic_waitloop32, \
	_Atomic(uint64_t)*: _atomic_waitloop64, _Atomic(int64_t)*: _atomic_waitloop64, \
	default: _atomic_waitloop_ptr \
)(ptr, val, o)

// Wait until an arbitrary condition is true AND another thread has notified the kernel via `atomic_wake_condition`. The implementation may occasionally wake spuriously (i.e with no corresponding `atomic_wake`), so the condition should always be re-checked after this function returns. `condition` may be evaluated an arbitrary number of times, even if it returned true
// `key` should be castable to a `uintptr_t` and is used to identify which sleeps `atomic_wake_condition` should interrupt. It does not need to point to valid memory, but it is ultimately hashed by the implementation in a way that optimizes collision rates for numbers that look like addresses to valid memory.
// It will not produce intended behavior to call `atomic_wake` for an `atomic_wait_until`, or `atomic_wake_condition` for an `atomic_wait` (i.e the intended waiters are unlikely to be woken).
#define atomic_wait_until(key, condition) _atomic_wait_until(key, condition, A_H_DEFAULT_SPIN, A_H_DEFAULT_YIELD)

// Notify an `atomic_wait_until` that its condition may have become true
// This will wake one or more threads waiting on the given address. `n` is the number of threads to wake, or `-1` to wake all threads. The implementation may wake more threads than requested, but will never wake fewer threads than requested or are waiting.
#define atomic_wake_condition(key, n) _atomic_wake_condition((void*)(key), n)

// Overload for `lock_acquire` with a memory order that must be one of `memory_order_relaxed`, `memory_order_acquire` or `memory_order_seq_cst`
static inline void lock_acquire_explicit(lock_t* lock, int32_t n, memory_order order){
	loop0: {}
	uint32_t v = atomic_load_explicit(lock, memory_order_relaxed);
	loop: {}
	int32_t v2 = (int32_t)(v&0x7FFFFFFF)-n;
	if(v2<0){
		if(atomic_compare_exchange_weak_explicit(lock, &v, v&0x80000000, memory_order_relaxed, memory_order_relaxed)){
			n = -v2;
			// block
			int count = A_H_DEFAULT_SPIN;
			while(count--) if((v = atomic_load_explicit(lock, memory_order_relaxed)) & 0x7FFFFFFF) goto loop; else thread_relax();
			count = A_H_DEFAULT_YIELD;
			while(count--) if((v = atomic_load_explicit(lock, memory_order_relaxed)) & 0x7FFFFFFF) goto loop; else thread_yield();
			if(!(v&0x80000000)) atomic_fetch_or_explicit(lock, 0x80000000, memory_order_relaxed), v |= 0x80000000;
			_atomic_wait32(lock, v);
			goto loop0;
		}
	}else if(atomic_compare_exchange_weak_explicit(lock, &v, (uint32_t)v2|(v&0x80000000), order, memory_order_relaxed)) return; // acquired
	goto loop;
}
// Acquire `n` slots from a `lock_t`. If those slots are not available, the function will wait until corresponding `lock_release` has released them. Note that this function may acquire only some of the `n` slots at a time, which may cause deadlocks when acquiring more than one slot. This function implies acquire memory ordering (see `lock_acquire_explicit`)
static inline void lock_acquire(lock_t* lock, int32_t n){ lock_acquire_explicit(lock, n, memory_order_acquire); }

// Overload for `lock_acquire_atomic` with a memory order that must be one of `memory_order_relaxed`, `memory_order_acquire` or `memory_order_seq_cst`
static inline void lock_acquire_atomic_explicit(lock_t* lock, int32_t n, memory_order order){
	uint32_t v = atomic_load_explicit(lock, memory_order_relaxed);
	loop: {}
	if((v&0x7FFFFFFF) < (uint32_t)n){
		// block
		int count = A_H_DEFAULT_SPIN;
		while(count--) if(((v=atomic_load_explicit(lock, memory_order_relaxed))&0x7FFFFFFF) >= (uint32_t)n) goto try_acq; else thread_relax();
		count = A_H_DEFAULT_YIELD;
		while(count--) if(((v=atomic_load_explicit(lock, memory_order_relaxed))&0x7FFFFFFF) >= (uint32_t)n) goto try_acq; else thread_yield();
		if(!(v&0x80000000)) atomic_fetch_or_explicit(lock, 0x80000000, memory_order_relaxed), v |= 0x80000000;
		_atomic_wait32(lock, v);
		uint32_t v = atomic_load_explicit(lock, memory_order_relaxed);
		if(v >= (uint32_t)n) goto try_acq;
		_atomic_wake32(lock, 1);
	}else try_acq: if(atomic_compare_exchange_weak_explicit(lock, &v, v-(uint32_t)n /* keeps wait flag */, order, memory_order_relaxed))
		return; // acquired
	goto loop;
}
// Acquire `n` slots from a `lock_t`. If those slots are not available, the function will wait until corresponding `lock_release` has released them. Note unlike `lock_acquire`, this function will not acquire any slots until all of them are available. This function implies acquire memory ordering (see `lock_acquire_atomic_explicit`)
static inline void lock_acquire_atomic(lock_t* lock, int32_t n){ lock_acquire_atomic_explicit(lock, n, memory_order_acquire); }

// Overload for `lock_wait` with a memory order that must be one of `memory_order_relaxed`, `memory_order_acquire` or `memory_order_seq_cst`
static inline void lock_wait_explicit(lock_t* lock, int32_t n, memory_order order){
	uint32_t v;
	// block
	int count = A_H_DEFAULT_SPIN;
	while(count--) if(n <= (int32_t)((v = atomic_load_explicit(lock, order))&0x7FFFFFFF)) return; else thread_relax();
	count = A_H_DEFAULT_YIELD;
	while(count--) if(n <= (int32_t)((v = atomic_load_explicit(lock, order))&0x7FFFFFFF)) return; else thread_yield();
	while(true){
		if(!(v&0x80000000)) atomic_fetch_or_explicit(lock, 0x80000000, memory_order_relaxed), v |= 0x80000000;
		_atomic_wait32(lock, v);
		if(n <= (int32_t)((v = atomic_load_explicit(lock, order))&0x7FFFFFFF)) return;
		_atomic_wake32(lock, 1);
	}
}
// Wait for `n` slots to become available on a `lock_t`. If those slots are not available, the function will wait until corresponding `lock_release` has released them. Nothing is acquired. Once those slots are available, they will stay available for other operations to potentially acquire. This function implies acquire memory ordering (see `lock_wait_explicit`)
static inline void lock_wait(lock_t* lock, int32_t n){ lock_wait_explicit(lock, n, memory_order_acquire); }

// Overload for `lock_try_acquire` with a memory order that must be one of `memory_order_relaxed`, `memory_order_acquire` or `memory_order_seq_cst`. The memory ordering only applies if the function succeeds (returns true)
static inline bool lock_try_acquire_explicit(lock_t* lock, int32_t n, memory_order order){
	uint32_t v = atomic_load_explicit(lock, memory_order_relaxed);
	loop: {}
	int32_t v2 = (int32_t)(v&0x7FFFFFFF)-n;
	if(v2<0) return false;
	if(atomic_compare_exchange_weak_explicit(lock, &v, (uint32_t)v2|(v&0x80000000), order, memory_order_relaxed)) return true; // acquired
	goto loop;
}
// Try to acquire `n` slots from a `lock_t`. If those slots are not available, the function will return false instead of waiting. This function implies acquire memory ordering if it succeeds (see `lock_try_acquire_explicit`)
static inline bool lock_try_acquire(lock_t* lock, int32_t n){ return lock_try_acquire_explicit(lock, n, memory_order_acquire); }

// Overload for `lock_release` with a memory order that must be one of `memory_order_relaxed`, `memory_order_release` or `memory_order_seq_cst`
static inline void lock_release_explicit(lock_t* lock, int32_t n, memory_order order){
	uint32_t wk = atomic_fetch_add_explicit(lock, n, order);
	if(wk&0x80000000){
		atomic_fetch_and_explicit(lock, 0x7FFFFFFF, memory_order_relaxed);
		// We need to wake at least this many waiters. By waking one more waiter we guarantee that the waiting flag is set again if there are indeed more waiters
		if(!n) return;
		wk &= 0x7FFFFFFF;
		_atomic_wake32(lock, (int)(wk+(wk<0x7FFFFFFF)));
	}
}
// Release `n` slots from a `lock_t`. Any threads waiting on another operation on this lock will have a chance to continue (i.e progress / return). The order of which threads progress first is not guaranteed but older waiters will typically progress sooner. This function implies release memory ordering (see `lock_release_explicit`)
static inline void lock_release(lock_t* lock, int32_t n){ lock_release_explicit(lock, n, memory_order_release); }

// Overload for `lock_fetch` with a memory order that must be one of `memory_order_relaxed`, `memory_order_acquire` or `memory_order_seq_cst`
static inline uint32_t lock_fetch_explicit(lock_t* lock, memory_order order){ return atomic_load_explicit(lock, order)&0x7FFFFFFF; }
// See how many slots are available on a `lock_t`. This function implies no memory ordering (see `lock_fetch_explicit`)
static inline uint32_t lock_fetch(lock_t* lock){ return atomic_load_explicit(lock, memory_order_relaxed)&0x7FFFFFFF; }

// Maximum number of slots a `lock_t` can hold available. Initializing the value to something higher than this limit, or releasing such that the value surpasses this limit, is undefined behavior
#define LOCK_MAX 2147483647

#if defined(__APPLE__) && !defined(APPLE_NO_UNSTABLE_ULOCK)
#pragma clang diagnostic pop
#endif

// L1 cache line is 64 bytes almost everywhere
#ifndef CACHE_LINE
// Size of a hardware cache line
// The good: Memory access for data stored on some cache line will typically make access to other data on the same cache line much faster
// The bad: Memory access for data stored the same cache line by different threads may incur the same contention overhead whether or not their memory regions actually overlap.
// The ugly: Memory contention and CPU cache is extremely complex, data stored on different (but close) cache lines may still incur some overhead (although usually less than when on the same cache line), and prefetching may cause contention penalty even when a pointer is not dereferenced.
// You may also redefine this macro before including the header to any power of two
#define CACHE_LINE 64
#elif (CACHE_LINE)&((CACHE_LINE)-1)
#error CACHE_LINE must be a power-of-two
#endif

#ifdef A_H_NODEPRECATE
#elif defined(__clang__) || defined(__GNUC__)
__attribute__((deprecated("Did you mean thread_sleep()?"))) unsigned sleep(unsigned);
#elif defined(_MSC_VER)
__declspec(deprecated("Did you mean thread_sleep()?")) unsigned sleep(unsigned);
#endif