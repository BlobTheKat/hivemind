#include <stdint.h>
#include <stddef.h>
#include <limits.h>

#define templated static inline

#if SIZE_MAX == UINT64_MAX
typedef struct ring_buffer_t{
	char* data;
	size_t cap_exp:8;
	size_t l:(sizeof(size_t)*CHAR_BIT)-8; size_t used;
} ring_buffer_t;
typedef struct ring_iterator_t{
	char *head, *end;
	size_t cap_exp:8, remaining:56;
} ring_iterator_t;
#else
typedef struct ring_buffer_t{
	char* data;
	size_t cap_exp, l, used;
} ring_buffer_t;
typedef struct ring_iterator_t{
	char *head, *end;
	size_t cap_exp, remaining;
} ring_iterator_t;
#endif

#if SIZE_MAX == UINT64_MAX
typedef struct array_buffer_t{
	char* data;
	size_t cap_exp:8, len:(sizeof(size_t)*CHAR_BIT)-8;
} array_buffer_t;
#else
typedef struct array_buffer_t{
	char* data;
	size_t cap_exp, len;
} array_buffer_t;
#endif
typedef struct array_iterator_t{
	char *head; size_t remaining;
} array_iterator_t;

// A fast approximation to 2^x, with a maximum relative error of about 0.088%
static inline float fast_exp2f(float x);

// Poor man's exponential. between 2^n and 2^(n+1), the function is completely linear. Maximum relative error ~6.15%
static inline float discrete_exp2f(float x);
// Poor man's logarithm. See also: `discrete_exp2f` (Poor man's exponential)
static inline float discrete_log2f(float x);

templated size_t ring_buffer_size(ring_buffer_t* obj);

templated size_t ring_buffer_push_garbage(ring_buffer_t* obj, size_t sz, bool _aligned);
templated void ring_buffer_push(ring_buffer_t* obj, void* d, size_t sz, bool aligned);
templated void ring_buffer_push_memset(ring_buffer_t* obj, char v, size_t sz, bool aligned);

templated void ring_buffer_shift_discard(ring_buffer_t* obj, size_t sz, bool aligned);
templated void ring_buffer_shift(ring_buffer_t* obj, void* d, size_t sz, bool aligned);

templated void ring_buffer_get(ring_buffer_t* obj, size_t i, void* d, size_t sz, bool aligned);
templated void ring_buffer_set(ring_buffer_t* obj, size_t i, void* d, size_t sz, bool aligned);

templated ring_iterator_t ring_buffer_iterator(ring_buffer_t* obj, size_t i, size_t count);

templated size_t ring_iterator_next(ring_iterator_t* obj, void* d, size_t sz, bool aligned);

templated void ring_buffer_clear(ring_buffer_t* obj);
templated void ring_buffer_destroy(ring_buffer_t* obj);


templated size_t array_buffer_size(array_buffer_t* obj);
templated void* array_buffer_data(array_buffer_t* obj);

templated void* array_buffer_push_garbage(array_buffer_t* obj, size_t sz);
templated void array_buffer_push(array_buffer_t* obj, void* d, size_t sz);
templated void array_buffer_push_memset(array_buffer_t* obj, int v, size_t sz);

templated void array_buffer_pop_discard(array_buffer_t* obj, size_t sz);
templated void array_buffer_pop(array_buffer_t* obj, void* d, size_t sz);

templated void array_buffer_get(array_buffer_t* obj, size_t i, void* d, size_t sz);
templated void array_buffer_set(array_buffer_t* obj, size_t i, void* d, size_t sz);

templated array_iterator_t array_buffer_iterator(array_buffer_t* obj, size_t i, size_t count);

templated size_t array_iterator_next(array_iterator_t* obj, void* d, size_t sz);

templated void array_buffer_clear(array_buffer_t* obj);
templated void array_buffer_destroy(array_buffer_t* obj);

#undef templated