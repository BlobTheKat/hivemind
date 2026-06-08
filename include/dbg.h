#pragma once
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#if defined(__clang__) || defined(__GNUC__)
#  define deprecate(msg) __attribute__((deprecated(msg)))
#elif defined(_MSC_VER)
#  define deprecate(msg) __declspec(deprecated(msg))
#else
#  define deprecate(msg)
#endif

#undef assert
#ifndef NDEBUG
	// Reimplement assert bc it's funny
	#undef assert
	#if defined(__clang__) || defined(__GNUC__)
		#define __assert(expr, msg, ...) (void)(__builtin_expect(!(expr), 0)&&(fprintf(stderr, "\x1b[31;1m=== Assertion failed ===\x1b[m\n%s\n\x1b[m", msg),__builtin_trap(),0))
		#define soft_assert(expr) (void)(__builtin_expect(!(expr),0)&&(__builtin_debugtrap(),0))
	#else
		#include <intrin.h>
		#define __assert(expr, msg, ...) (void)(!(expr)&&(fprintf(stderr, "\x1b[31;1m=== Assertion failed ===\x1b[m\n%s\n\x1b[m", msg),__fastfail(FAST_FAIL_FATAL_APP_EXIT),0))
		#define soft_assert(expr) (void)(!(expr)&&(__debugbreak(),0))
	#endif
	#define assert(...) __assert(__VA_ARGS__,#__VA_ARGS__)
	#define DEBUG 1
	#ifdef NO_SOFT_ASSERT
		#undef soft_assert
		#define soft_assert(...) (void)(0)
	#endif
#else
	#define soft_assert(...) (void)(0)
	#define assert(...) (void)(0)
	#define DEBUG 0
#endif

#define sbr__(...) __VA_ARGS__
#if defined(_WIN32)
	#include <intrin.h>
	#define breakpoint(...) (printf("\x1b[31;1m=== Breakpoint ===\x1b[m\n" __VA_OPT__("%s\n", (__VA_ARGS__))),__debugbreak())
#else
	#include <signal.h>
	#define breakpoint(...) (printf("\x1b[31;1m=== Breakpoint ===\x1b[m\n" __VA_OPT__("%s\n", (__VA_ARGS__))),raise(SIGTRAP))
#endif

static void hexdump(const void *data, size_t len){
	printf("\x1b[32m=== %p (%zu bytes) ===\x1b[m\n", data, len);
	if(!len) return;
	const uint8_t *p = (const uint8_t *)data;
	char* str = (char*) malloc(len*3 + ((len+3)>>2));
	char* str2 = str;
	const char dig[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
	for(size_t i = 0; i < len; i++){
		uint8_t byte = p[i];
		str2[0] = dig[byte>>4]; str2[1] = dig[byte&15]; str2[2] = ' ';
		str2 += 3;
		if((i&3)==3)
			*str2++ = (i&15)==15 ? '\n' : ' ';
	}
	str2[-1] = '\n';
	fwrite(str, 1, (size_t)(str2-str), stdout);
	free(str);
}

#ifdef NO_STDIO
#include "stdarg.h"
deprecate("printf() with -DNO_STDIO") static int (*const printf_2)(const char* _, ...) = printf;
#define printf printf_2
deprecate("scanf() with -DNO_STDIO") static int (*const scanf_2)(const char* _, ...) = scanf;
#define scanf scanf_2
deprecate("vprintf() with -DNO_STDIO") static int (*const vprintf_2)(const char* _, va_list _2) = vprintf;
#define vprintf vprintf_2
deprecate("vscanf() with -DNO_STDIO") static int (*const vscanf_2)(const char* _, va_list _2) = vscanf;
#define vscanf vscanf_2
deprecate("getchar() with -DNO_STDIO") static int (*const getchar_2)() = getchar;
#define getchar getchar_2
deprecate("putchar() with -DNO_STDIO") static int (*const putchar_2)(int) = putchar;
#define putchar putchar_2

#if !defined(__cplusplus) && (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 201112L)
	// pre-C11
	deprecate("gets() with -DNO_STDIO") static char* (*const gets_2)(char*) = gets;
	#define gets gets_2
#endif
deprecate("puts() with -DNO_STDIO") static int (*const puts_2)(const char*) = puts;
#define puts puts_2
// perror is maybe important in some cases
//deprecate("perror() with -DNO_STDIO") int perror(...);
#endif

#ifdef TSAN
_Atomic uint32_t __tsan_sync;
// thread sanitizer doesn't consider atomic_thread_fence to be a synchronization edge unfortunately
#define tsan_fence(m) atomic_fetch_add_explicit(&__tsan_sync, 1, m)
#else
#define tsan_fence(m) 0
#endif