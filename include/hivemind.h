#pragma once
#ifdef __cplusplus
extern "C" {
#endif
#include "x.h"

// [IP]/port/mtu/time/rand_b64
// See `hivemind_pipe_to_string()` and `hivemind_pipe_from_string()`
static const size_t HIVEMIND_PIPE_STR_MAX_LEN = 89;

// The main server struct. See note on `hivemind_init()`. This struct is somewhat large and includes some padding for ABI stability.
// Only fields declared and documented in this header file are guaranteed to be ABI-stable. The remainder of the struct (including all "padding") is reserved for internal use and should not be touched for the entire active lifetime of the server (i.e from `hivemind_init()` until the `on_close()` callback passed to `hivemind_quit()` is called).
typedef struct{
	union{
#ifdef __cplusplus
		alignas(16)
#else
		_Alignas(16)
#endif
		char __bytes[256];
		struct{
			// IP address returned by the reflection test, which is used to determine the public IP when constructing pipes. Note that this may be an IPv4-mapped IPv6 address. This value can be written after `hivemind_init()` but before `hivemind_start()`, see the note on `hivemind_start()`.
			ip_addr_t addr;
			// Port and MTU used when constructing pipes, all in little-endian. These values can be written after `hivemind_init()` but before `hivemind_start()`, see the note on `hivemind_start()`.
			// ```c
			// union{
			// 	struct{  uint16_t port_le, mtu_le;  };
			// 	uint32_t port_mtu_packed_le;
			// 	struct{ uint8_t port_lo, port_hi, mtu_lo, mtu_hi; };
			// };
			// ```
			union{ struct{ uint16_t port_le, mtu_le; }; uint32_t port_mtu_packed_le; struct{ uint8_t port_lo, port_hi, mtu_lo, mtu_hi; }; };

			// Encryption bypass allows hivemind to avoid encrypting traffic within an internal network, saving both CPU and a small amount of bandwidth.
			// To prevent data corruption, accidental replays, etc..., a checksum is still enforced for every packet (specifically, CRC64) as well as other policies similar to encrypted traffic, the main difference being that these policies are only designed to avoid accidental mishaps. A malicious actor with access to your internal network can cause a lot more issues than just that of confidentiality (e.g Denial of service, Message/ack forgery, etc...)
			// You can set individual CIDR mask for IPv6 and IPv4. This mask can be up to 16 bits longer to also match the high bits of the port.
			// The default is /128 for IPv6 (Match IP but port can differ) and /32 for IPv4 (ditto), effectively enabling encryption bypass for traffic to the same machine
			// This setting should be identical between servers that expect to use encryption bypass. Using different settings may lead to one server rejecting packets sent by another, either because received traffic is expected to be encrypted but isn't, or vice versa.
			// See also: `network_bypass_prefix_v6`, `network_bypass_prefix_v4`
			uint8_t encryption_bypass_prefix_v6, encryption_bypass_prefix_v4;
			// Network bypass allows hivemind to avoid the kernel's network stack, instead using pipes or UNIX domain sockets, saving a lot of CPU
			// Hivemind sets its pipes under /var/run/hivemind on UNIX-based systems and \\.\hivemind\ on Windows
			// You can set individual CIDR mask for IPv6 and IPv4. This mask can be up to 16 bits longer to also match the high bits of the port.
			// The default is /144 for IPv6 (Match IP and port exactly) and /48 for IPv4 (ditto), effectively disabling network bypass
			// This setting should be identical between servers that expect to use network bypass. Using different settings may lead to one server rejecting packets sent by another.
			// Note that unless hivemind is built with -DHIVEMIND_NO_LOCAL_BYPASS, traffic to the same IP and port will always bypass both the network stack and the kernel, and the message event is delivered synchronously and without copying (see note on `hivemind_send`)
			// See also: `encryption_bypass_prefix_v6`, `encryption_bypass_prefix_v4`
			uint8_t network_bypass_prefix_v6, network_bypass_prefix_v4;
			// User data passed to `on_msg` / `on_close` callbacks as the first argument. Default is a pointer to the hivemind server. This value can be written after `hivemind_init()` but before `hivemind_start()`, see the note on `hivemind_init()`.
			void* udata;
			// How long a connection is "remembered" for, in microseconds. Key exchanges are relatively cheap so this affects memory usage more than performance
			// This value dictates the longest that a network partition can last before delivery guarantees become invalid.
			// This value can be written after `hivemind_init()` but before `hivemind_start()`, see the note on `hivemind_init()`.
			uint64_t state_lifetime;
		};
		// Combined IP address, port and MTU used when constructing pipes. This is a view over the exact same memory as the `addr`, `port_le` and `mtu_le` fields. The same write restrictions apply.
		uint32_t dwords[5];
	};
} hivemind_server_t;
_Static_assert(sizeof(hivemind_server_t) == 256, "");

// 40-byte struct representing a pipe. This is an aggregate struct, you can pass it around, reconstruct it, etc. All fields are public and ABI-stable. The `id` field is a random 160-bit identifier that is used to distinguish pipes with the same address. Note that fields are all in little-endian format, this means the byte-for-byte representation is identical on all machine, allowing you to safely serialize and deserialize pipes with e.g `memcpy()`. If you want a nicer human-readable format, see `hivemind_pipe_to_string()` and `hivemind_pipe_from_string()`.
typedef struct hivemind_pipe_t{ union{
	struct{
		ip_addr_t addr;
		uint16_t port_le, mtu_le;
		uint32_t id[5];
	};
	uint32_t dwords[10];
	uint8_t bytes[40];
}; } hivemind_pipe_t;
_Static_assert(sizeof(hivemind_pipe_t) == 40, "");

typedef void (*hivemind_generic_fn_t)(void*);
typedef void (*hivemind_on_msg_fn_t)(void*, const uint8_t*, size_t, void*);
typedef void* (*hivemind_pipe_restore_fn_t)(void*, uint8_t*, size_t);
typedef void (*hivemind_pipe_finish_fn_t)(void*, void*);

// See `hivemind_start()`
static const ip_addr_t HIVEMIND_WAN_V4 = {.words={0,0,0,0,0,0xffff,0x0808,0x0808}}; // ::ffff:8.8.8.8
static const ip_addr_t HIVEMIND_WAN_V6 = {.bytes={32,1,72,96,72,96,0,0,0,0,0,0,8,8,8,8}}; // 2001:4860:4860::8888
// Initialize a server with the given master key and message callback
// You are expected to allocate the server struct yourself, and it must have a stable address until the callback handler passed to `hivemind_quit()` is called
// Additional non-essential parameters can be configured after this function but before `hivemind_start()`. These include
// `server.udata`: Userdata passed as the first argument to `on_msg` and `on_close`
// `server.state_lifetime`: Connection state lifetime and maximum partition length, in microseconds
void hivemind_init(hivemind_server_t* server, const uint8_t master_key[32], hivemind_on_msg_fn_t on_msg);
// Start listening on the given address, with an optional reflection test IP (this is used to discover the local address, port and MTU). Returns true on success.
// If you would like to supply your own address, port, MTU or any combination of those, you can write to the corresponding fields in the server struct after `hivemind_init()` and before `hivemind_start()`, and they will be used instead of the results from the reflection test. When all 3 are provided before `hivemind_start()`, the reflection test is skipped and the field is unused (in any other case, passing `{0}` may fail).
// You may also optionally load the server state from a file (`char* filename`). This will restore all pipes and connections from a previous `hivemind_quit()` that saved the state to that same file. This feature is useful for essential services that should not be disconnected from your network due to e.g a periodic machine restart. If `filename` is not `NULL`, the `pipe_restore` function may be called any number of times with any pipe-associated data that was serialized on last quit. The data passed to the function invocation is a temporary buffer, you may write within its bounds. It is discarded once the server starts. The buffer is also guaranteed to be aligned to at least 4 bytes.
bool hivemind_start(hivemind_server_t* server, remote_t where, ip_addr_t reflect_test, /*nullable*/ const char* filename, hivemind_pipe_restore_fn_t pipe_restore);
// Quit the server, optionally saving state to a file. The `on_close` callback will be called once the server is fully stopped. The server struct can be reused / freed from the moment this callback is called.
// Optionally provide a file to save the state to, and a pipe finalization callback. If the callback is specified, it will be called for every remaining pipe on the server at the time of being stopped. Within this callback, it is possible to serialize each pipe's state using the `hivemind_request_buffer` function.
// Note that the `pipe_finish` callback, if not `NULL`, will be called even if `filename == NULL`. In such case, any calls to `hivemind_request_buffer` will return `NULL`, indicating that state is not being serialized.
void hivemind_quit(hivemind_server_t* server, hivemind_generic_fn_t on_close, /*nullable*/ const char* filename, hivemind_pipe_finish_fn_t pipe_finish);

// See `hivemind_quit`. Calling this function outside of the `pipe_finish` callback is undefined behavior.
// This function returns a buffer of the specified size. Any data written to this buffer before the callback returns will be saved to disk and passed to the `pipe_restore` callback of `hivemind_start` the next time the server is started. This function may be called more than once, to request a bigger (or smaller) allocation. The new buffer will contain the contents of the old buffer (any new bytes are uninitialized). This typically does not involve a copy.
uint8_t* hivemind_request_buffer(size_t sz);

// Detach a received packet, so it can be safely modified, and accessed after the callback returns. You must call `hivemind_packet_free()` on the returned pointer once you are done with it. The returned pointer may or may not be the same as the input pointer, however you should not use the input pointer after calling this function. Note that there are still no alignment guarantees on the returned pointer.
// This function very rarely needs to actually copy the packet. Most of the time it just marks the packet as detached, so that it is not freed after your callback returns.
// Calling this function outside of a callback invocation is undefined behavior
uint8_t* hivemind_packet_detach(const uint8_t* packet);
// Free a detached packet. You must call this function on the pointer returned by `hivemind_packet_detach()` once you are done with the packet. Much like `free()`, this function also accepts null pointers and is a no-op in that case.
// Can be called at any time after `hivemind_packet_detach()`, even from another thread (this must be at least minimally synchronized, e.g acq/rel).
void hivemind_packet_free(const uint8_t* packet);

// By default, a callback invocation guarantees the current pipe is available (at least until the callback returns). To offer this guarantee, `hivemind_close_pipe()` may block until callbacks are done. If you want to release this guarantee early, you can call `hivemind_pipe_unlock()`.
// This primarily serves protect you from nasty use-after-frees, as even reference counting on its own may not always be enough (you may have freed your userdata between when the packet was accepted and when your callback increments the refcount).
// For the example of refence counting, you can increment the refcount, then call `hivemind_pipe_unlock()`. Doing this, when concurrently receiving a message and closing the pipe, guarantees one of two things will happen:
// 1. `hivemind_close_pipe()` blocks until `hivemind_pipe_unlock()` is called, and the closer thread will see the new refcount
// 2. `hivemind_close_pipe()` is early enough and the message is rejected, your message callback was never invoked.
// Calling this function outside of a callback invocation is undefined behavior
void hivemind_pipe_unlock();

// Send a message to the given pipe. The message is guaranteed to be delivered as long as the pipe is not closed, and there is no network partition longer than the state cutoff, as defined by the receiver. Messages larger than the minimum MTU (minus overhead) will be fragmented (fragmentation primarily affects worst-case latency).
// The message will be copied, `msg` does not need to remain valid after this function returns. This function also performs all of the necessary encryption itself. If the current thread is important (e.g UI thread) and the message is large, you should probably defer this call to another thread
// BEWARE: If the destination pipe has the same address as the server, the message may be delivered synchronously and copy-less. It is therefore possible for the `on_msg` callback to be called before `hivemind_send()` returns. (Note that `hivemind_packet_detach()` / `hivemind_packet_free()` still work as expected even in this case). This behavior can be disabled by building hivemind with `-DHIVEMIND_NO_LOCAL_BYPASS`.
void hivemind_send(hivemind_server_t* server, const hivemind_pipe_t* to, const uint8_t* msg, size_t len);

// Create a new pipe to listen on. The `udata` pointer is not interpreted by the library, but will be passed to the `on_msg` callback when a message is received on this pipe. For concurrency and use-after-free concerns, see the note on `hivemind_pipe_unlock()`.
void hivemind_create_pipe(hivemind_server_t* server, hivemind_pipe_t* pipe, void* udata);
// Close a pipe. The return value is the `udata` pointer that was passed to `hivemind_create_pipe()`, or null if the pipe was not found. If the same pipe is closed more than once, only one of them will return the userdata, all others will return null. For concurrency and use-after-free concerns, see the note on `hivemind_pipe_unlock()`.
void* hivemind_close_pipe(hivemind_server_t* server, const hivemind_pipe_t* pipe);

// Get the string representation of a pipe, which currently looks like `[IP]/port/mtu/time/rand_b64`. The string is null-terminated and its length (excluding the null character) is returned.
size_t hivemind_pipe_to_string(const hivemind_pipe_t* pipe, char out[HIVEMIND_PIPE_STR_MAX_LEN]);
// Parse a string representation of a pipe, which currently looks like `[IP]/port/mtu/time/rand_b64`. If the string represents a valid pipe, the function returns true and writes the result to `pipe`. Otherwise, it returns false and the contents of `pipe` are invalidated.
bool hivemind_pipe_from_string(hivemind_pipe_t* pipe, const char in[HIVEMIND_PIPE_STR_MAX_LEN]);

#ifdef __cplusplus
} /* extern "C" */
#endif