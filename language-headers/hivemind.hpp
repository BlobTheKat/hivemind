#pragma once
#include <string>
#include <utility>
#include <array>
namespace hivemind{
#include "hivemind.h"

// 40-byte struct representing a pipe. This is an aggregate struct, you can pass it around, reconstruct it, etc. All fields are public and ABI-stable. The `id` field is a random 160-bit identifier that is used to distinguish pipes with the same address. Note that fields are all in little-endian format, this means the byte-for-byte representation is identical on all machine, allowing you to safely serialize and deserialize pipes with e.g `memcpy()`. If you want a nicer human-readable format, see `hivemind_pipe_to_string()` and `hivemind_pipe_from_string()`.
struct HivemindPipe: hivemind_pipe_t{
	// Get the string representation of a pipe, which currently looks like `[IP]/port/mtu/time/rand_b64`.
	std::string to_string(){
		char out[HIVEMIND_PIPE_STR_MAX_LEN];
		return {out, hivemind_pipe_to_string(this, out)};
	}
	// Parse a string representation of a pipe, which currently looks like `[IP]/port/mtu/time/rand_b64`. If the string does not represents a valid pipe, the returned pipe will be zero-initialized, and `is_valid()` will return false (all-zero is never a valid pipe).
	static HivemindPipe from_string(const std::string& in){
		HivemindPipe p;
		if(!hivemind_pipe_from_string(&p, in.c_str()))
			memset(&p, 0, sizeof(p));
		return p;
	}
	bool operator==(const HivemindPipe& other) const{
		return memcmp(this, &other, sizeof(hivemind_pipe_t)) == 0;
	}
	bool is_valid() const{
		// A pipe is considered valid if it has a non-zero address and port. Note that this does not necessarily mean the pipe is actually usable, as the remote peer may be offline, or there may be a network partition, etc.
		for(size_t i = 0; i < 10; i++){
			if(this->dwords[i] != 0) return true;
		}
		return false;
	}
	bool operator!=(const HivemindPipe& other) const{ return !(*this == other); }
	operator bool() const{ return this->is_valid(); }
	bool operator!() const{ return !this->is_valid(); }
};

// The main server struct. See note on `hivemind_init()`. This struct is somewhat large and includes some padding for ABI stability.
// Only fields declared and documented in this header file are guaranteed to be ABI-stable. The remainder of the struct (including all "padding") is reserved for internal use and should not be touched for the entire active lifetime of the server (i.e from `hivemind_init()` until the `on_close()` callback passed to `hivemind_quit()` is called).
template<typename T = HivemindServer<>, typename P = void> struct HivemindServer: private hivemind_server_t{

	using MsgFn = void (*)(T*, const uint8_t*, size_t, P*);
	using GenericFn = void (*)(T*);
	using PipeRestoreFn = P* (*)(T*,uint8_t*,size_t);
	using PipeFinishFn = void (*)(T*,P*);

	HivemindServer(const HivemindServer&) = delete;
	HivemindServer& operator=(const HivemindServer&) = delete;
	HivemindServer(HivemindServer&&) = delete;
	HivemindServer& operator=(HivemindServer&&) = delete;
	
	HivemindServer() = default;
	template<typename... Args>
	HivemindServer(Args... a){ this->init(std::forward<Args>(a)...); }

	T* udata(){ return hivemind_server_t::udata; }
	void udata(T* u){ hivemind_server_t::udata = u; }
	uint64_t state_lifetime(){ return hivemind_server_t::state_lifetime; }
	void state_lifetime(uint64_t s){ hivemind_server_t::state_lifetime = s; }

	// Initialize a server with the given master key, message callback, (optional) state lifetime in microseconds, and optionally load state from a file (not implemented yet)
	void init(const uint8_t master_key[32], MsgFn on_msg){
		hivemind_init(this, master_key, (hivemind_on_msg_fn_t)on_msg);
	}
	
	// If you would like to supply your own address, port, MTU or any combination of those to override the results from the reflection test, you can call `set_self()` before calling `start()`. If all three parameters are non-zero, the reflection test is skipped entirely.
	void set_self(ip_addr_t addr, uint16_t port, uint16_t mtu = 0){
		this->addr = addr;
		this->port_mtu_bytes[0] = port & 0xFF;
		this->port_mtu_bytes[1] = port >> 8;
		this->port_mtu_bytes[2] = mtu & 0xFF;
		this->port_mtu_bytes[3] = mtu >> 8;
	}
	// Start listening on the given address, with an optional reflection test IP (this is used to discover the local address, port and MTU). Returns true on success.
	bool start(remote_t where, ip_addr_t reflect_test = HIVEMIND_WAN, const char* filename = 0, PipeRestoreFn pipe_restore = 0){
		return hivemind_start(this, where, reflect_test, filename, (hivemind_pipe_restore_fn_t) pipe_restore);
	}
	// Quit the server, optionally saving state to a file (not implemented yet). The callback will be called once the server is fully stopped. The server struct can be reused / freed from the moment this callback is called.
	void quit(GenericFn on_close = 0, /*nullable*/ const char* filename = 0, PipeFinishFn pipe_finish = 0){
		hivemind_quit(this, (void(*)(void*))on_close, filename, (hivemind_pipe_finish_fn_t) pipe_finish);
	}
	// Send a message to the given pipe. The message is guaranteed to be delivered as long as the pipe is not closed, and there is no network partition longer than the state cutoff, as defined by the receiver. Messages larger than the minimum MTU (minus overhead) will be fragmented (fragmentation primarily affects worst-case latency).
	// The message will be copied, `msg` does not need to remain valid after this function returns. This function also performs all of the necessary encryption itself. If the current thread is important (e.g UI thread) and the message is large, you should probably defer this call to another thread
	// BEWARE: If the destination pipe has the same address as the server, the message may be delivered synchronously and copy-less. It is therefore possible for the `on_msg` callback to be called before `hivemind_send()` returns. (Note that `hivemind_packet_detach()` / `hivemind_packet_free()` still work as expected even in this case). This behavior can be disabled by building hivemind with `-DHIVEMIND_NO_LOCAL_BYPASS`.
	void send(const HivemindPipe& to, const uint8_t* msg, size_t len){
		hivemind_send(this, to, msg, len);
	}
	// Overload of `send()` that accepts any type that has a contiguous data representation, such as `std::vector`, `std::string`, `std::array`, etc.
	template<typename T> void send(const HivemindPipe& to, const T& data){
		hivemind_send(this, to, (uint8_t*) data.data(), (const size_t&) data.size());
	}
	// Create a new pipe to listen on. The `udata` pointer is not interpreted by the library, but will be passed to the `on_msg` callback when a message is received on this pipe. For concurrency and use-after-free concerns, see the note on `hivemind_pipe_unlock()`.
	HivemindPipe create_pipe(P* udata = 0){
		hivemind_pipe_t pipe;
		hivemind_create_pipe(this, &pipe, udata);
		return (HivemindPipe) pipe;
	}
	// Close a pipe. The return value is the `udata` pointer that was passed to `hivemind_create_pipe()`, or null if the pipe was not found. If the same pipe is closed more than once, only one of them will return the userdata, all others will return null. For concurrency and use-after-free concerns, see the note on `hivemind_pipe_unlock()`.
	P* delete_pipe(const HivemindPipe& pipe){
		return hivemind_close_pipe(this, &pipe);
	}
};

static std::array<uint8_t, 32> master_key_from_file(const char* filename){
	std::array<uint8_t, 32> key;
	x_file_t fd = x_open(filename);
	if(x_getsize(fd) < 32){
		// Generate new key
		x_randombytes(key.data(), 32);
		x_write(fd, 0, key.data(), 32);
	}else{
		// Load existing key
		x_read(fd, 0, key.data(), 32);
	}
	x_close(fd);
	return key;
}
}