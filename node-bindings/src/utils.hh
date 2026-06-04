#include <napi.h>
#include <cstring>

template<typename T> struct alignas(T) slot{
	char value[sizeof(T)];
	constexpr slot(){}
	
	constexpr T& operator*() const{ return *(T*)value; }
	constexpr T* operator->() const{ return (T*)value; }
	constexpr operator const T&() const{return *(const T*)value;}
	constexpr operator T&(){return *(const T*)value;}

	template<typename T2 = T, typename... X>
	constexpr void construct(X... a){ new (value) T2(a...); }
	template<typename T2 = T, typename T3 = T, typename... X>
	constexpr void replace(X... a){ ((T3*)value)->~T(); new (value) T2(a...); }
	template<typename T2 = T>
	constexpr void destruct(){ ((T2*)value)->~T2(); }
	constexpr T copy() const{return *(T*)value;}
	constexpr T&& move() const{return move(*(T*)value);}
};

inline size_t Napi_utf8_copy(const Napi::String& str, char out[], size_t maxlen){
	napi_status status = napi_get_value_string_utf8(str.Env(), str, out, maxlen, &maxlen);
	if(status != napi_ok){
		if(maxlen) out[0] = '\0';
		return 0;
	}
	return maxlen;
}