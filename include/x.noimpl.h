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
typedef SIZE_T size_t;
typedef HANDLE x_file_t;
typedef struct{
	HANDLE hFind;
	_WIN32_FIND_DATAA a;
} *x_folder_list_t;
typedef SOCKET x_socket_t;
static const x_file_t X_FILE_INVALID = (x_file_t) INVALID_HANDLE_VALUE;
static const x_socket_t X_SOCKET_INVALID = (x_socket_t) INVALID_SOCKET;
#else
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <dirent.h>
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdatomic.h>

typedef int x_file_t;
typedef DIR* x_folder_list_t;
static const x_file_t X_FILE_INVALID = (x_file_t) -1;
typedef int x_socket_t;
static const x_socket_t X_SOCKET_INVALID = (x_socket_t) -1;
#endif

union x_userdata_t{
	void* ptr;
	x_socket_t socket;
	uint32_t u32;
	uintptr_t uptr;
};

typedef struct{
	uint32_t type;
	union x_userdata_t data;
} x_event_t;

#if defined(__linux__)
typedef struct{
	int _1, _2;
	uint64_t _5;
	uint32_t _4;
	uint32_t _4[60];
} x_event_queue_t;
#else
typedef struct{
	int _1; uint32_t _2;
	uint64_t _3;
	uint32_t _4[((sizeof(uintptr_t)>>2)+1)*20];
} x_event_queue_t;
#endif

static const uint64_t X_FILE_NOT_FOUND = 0, X_FILE_UNKNOWN = 0,
	X_FILE_TYPE_FILE = 1,
	X_FILE_TYPE_FOLDER = 2,
	X_FILE_TYPE_SPECIAL = 3;
typedef struct{
	uint64_t type:8;
	uint64_t modified:56;
	uint64_t size;
} x_stat_t;

static const uint32_t X_EVENT_SIGNAL = 256, X_EVENT_TIMEOUT = 512, X_EVENT_WAKE = 1024, X_EVENT_EOF = 8192, X_EVENT_CLOSE = 16, X_EVENT_READABLE = 1, X_EVENT_WRITABLE = 4, X_EVENT_ERROR = 8;

typedef union{
	struct{ uint8_t bytes[16]; };
	struct{ uint16_t words[8]; };
	struct{ uint32_t dwords[4]; };
} ip_addr_t;

typedef struct{
	ip_addr_t addr;
	uint16_t port, mtu;
	uint32_t interface;
} remote_t;

static const int IP_STR_MAX_LEN = 40;

// Create a directory
static bool x_mkdir(const char* name);

// Delete a file or empty directory
static bool x_remove(const char* name);

// Open a directory for listing files
static x_folder_list_t x_dir_open(const char* name);
// Get the next file in a directory listing, or 0 (NULL) if there are no more files. The returned string is valid until the next call to x_dir_next() or x_dir_close()
static char* x_dir_next(x_folder_list_t dir);
// Close a directory listing
static void x_dir_close(x_folder_list_t dir);

// Open a file from a null-terminated string specifying the pathname
static x_file_t x_open(const char* name);

// Move a file atomically
static bool x_move(const char* old_name, const char* new_name);


// Get the size of a file in bytes
static uint64_t x_getsize(x_file_t fd);

// Read `count` bytes from fd, starting at offset `start`. Data is written to `buf`, which is expected to be valid, writable memory for at least `count` bytes. The number of bytes actually read is returned, which may be less than the number of bytes requested if the end of the file was found, or 0 if the file could not be read from
static size_t x_read(x_file_t fd, uint64_t start, void* buf, size_t count);

// Write `count` bytes to fd, starting at offset `start`. Data is read from `buf`, which is expected to be valid, readable memory for at least `count` bytes. The number of bytes actually written is returned, which may be less than the number of bytes requested under special circumstances (old systems, disk full), or 0 if the file could not be written to
static size_t x_write(x_file_t fd, uint64_t start, const void* buf, size_t count);

// Set the size of a file in bytes. If the size is smaller than the current size, the file is truncated, otherwise it is expanded and the additional bytes are all set to 0
static bool x_setsize(x_file_t fd, uint64_t sz);

// Close a file. The x_file_t becomes invalid before the function returns and new calls to x_open may create x_file_t handles that compare == to this one. It is best practice to completely forget the old file handle and never assume anything about it after it has been closed, much like you would with a pointer that has been free()'d
static void x_close(x_file_t fd);

// Maps a region of a x_file_t to memory, from page `off` (byte `off * X_PAGE_SIZE`) to, and excluding, page `off+sz` (byte `(off+sz) * X_PAGE_SIZE`)
// If copy == false, the memory region returned will be a live view into the file. Anything written to this memory will be written back to the file and visible to any other process that has also mapped the same region. Note that mixing writes via both x_read()/x_write() and accessing the mapped memory results in unpredictable behavior. Writes may fail, be torn, or not be visible immediately.
// If copy == true, the memory region will be populated with a copy of the file's contents, and any modifications will not be written back to the file, and effectively becomes private memory much like x_pagealloc(). It is then safe to x_read()/x_write() the region, as it will not affect the mapped memory in any way
// In either case, the returned pointer should be freed with x_pagefree()
// On failure, 0 (NULL) is returned
static void* x_mapfile(x_file_t fd, uint64_t off, size_t sz, bool copy);

// Allocate `sz` pages (`sz * X_PAGE_SIZE` bytes) of memory, with all bytes initially set to 0
static void* x_pagealloc(size_t sz);

// Free memory returned by x_pagealloc() or x_mapfile(). `sz` must exactly match the size of the allocation/mapping. Freeing only part of an allocation/mapping is not allowed.
static void x_pagefree(void* ptr, size_t sz);

// Check if a file exists and get metadata
static x_stat_t x_stat(const char* name);

// Page size used by X (always 65536). Specifically, x_mapfile()/x_pagealloc()/x_pagefree() have all their size/offset arguments measured in pages of 65536 bytes. Converting from pages to bytes or vice versa is as simple a shifting right (>>) or left (<<) 16 bits respectively
static const size_t X_PAGE_SIZE = 65536;

// Parse an IP, such as "1.2.3.4", "2001:db8:1001:2002:db8::1234", or "::ffff:192.168.1.42", into an `ip_addr_t`
static ip_addr_t ip_from_string(const char* str);

// Find the index of a network interface from its name, such as "eth0" or "en0". Returns 0 if the interface was not found (0 is never a valid interface index).
static uint32_t interface_from_str(const char* interface_name);

// Stringify an ip_addr_t into a human-readable string, such as "1.2.3.4" or "2001:db8:1001:2002:db8::1234"
static void ip_to_string(ip_addr_t addr, char out[IP_STR_MAX_LEN]);


// Create a new UDP socket which will automatically select a port/address/interface as needed, ideal for clients
static x_socket_t x_udp_auto();

// Get information about which IP and port would be used to send a packet to a specific address, as well as optionally the MTU for that path. The MTU here only counts the maximum UDP payload length, Appropriate IPv4/IPv6 or UDP header sizes are subtracted for you.
static void x_udp_reflect(x_socket_t s, ip_addr_t to, remote_t* from);

// Set socket options for a UDP socket, specifically the send and receive buffer sizes. Note that these sizes are not guaranteed to be set to exactly what you specify, the operating system may silently round them up or down, and there may be hard limits on how large they can be.
static bool x_udp_opts(x_socket_t s, size_t send_buf, size_t recv_buf);

// Create a new UDP socket with manually specified port/address/interface, ideal for servers.
// Pass `NULL` to `interface` to automatically pick the interface based on `addr`, or listen on all interfaces if `addr` is zero (::).
// Pass `0` to `port` to have a port picked for you, usually in the "ephemeral range" (e.g 32768-60999 on linux, 49152-65535 elsewhere)
static x_socket_t x_udp_bound(remote_t addr);

// Send a UDP packet from `msg` of exactly `msglen` bytes to the specified IP and port. The address/port to send from, as well as the interface, is determined by `sock` and how it was created (see `x_udp_auto` and `x_udp_bound`). UDP supports message sizes as low as zero bytes or as high as 65535 bytes. Anything more will fail (return false)
static bool x_udp_send(x_socket_t sock, remote_t to, const void* msg, size_t msglen);

// Read a UDP packet into `msg` of up to `maxlen` bytes (any additional bytes that did not fit are discarded). The IP and port are written to `from` if it is not null. The address/port to receive from, as well as the interface, is determined by `sock` and how it was created (see `x_udp_auto` and `x_udp_bound`). UDP supports message sizes as low as zero bytes or, in theory, as high as 65527 bytes, however most real-world networks will impose much lower limits (typically around 1500 bytes). On success, the number of bytes read is returned. On failure, -1 is returned.
static int x_udp_next_read(x_socket_t sock, remote_t* from, void* msg, size_t maxlen);

// Close a UDP socket. This will free up the address/port that was used by this socket, and emit an X_EVENT_CLOSE event for that socket.
static void x_udp_close(x_socket_t sock);
// Free a socket. Any operations on this socket become invalid. The socket is closed if it was not already. Note that if this socket was already attached to an event queue, you may still receive delayed events up until its corresponding close event (which will not be fired unless you called `x_*_close`)
static void x_socket_free(x_socket_t sock);

// Construct an event queue object. If construction fails for any reason, false is returned and `out` is unmodified
static bool x_event_queue_init(x_event_queue_t* out);

// Add a socket to an event queue, which will emit X_EVENT_READABLE/X_EVENT_WRITABLE/X_EVENT_CLOSED events when the socket becomes readable/writable/closed respectively
static bool x_event_queue_add(x_event_queue_t* queue, x_socket_t sock, union x_userdata_t data);

// Wait for the next event, or up until `timeout` nanoseconds (in which case an X_EVENT_TIMEOUT event is returned), or a process signal is received (in which case an X_EVENT_SIGNAL event is returned). Waiting on the same event queue from multiple threads is well-defined: exactly one of the waiting threads will receive any given event. Which thread receives it is not defined, it may be different even for the same socket, and may not be evenly distributed. A `timeout` of -1 means to wait indefinitely until an event occurs.
static x_event_t x_event_queue_wait(x_event_queue_t* queue, uint64_t timeout);

// Remove a socket from an event queue, see `x_event_queue_add`.
static bool x_event_queue_remove(x_event_queue_t* queue, x_socket_t sock);

// Emits a X_EVENT_WAKE event on an event queue, optionally, after an amount of time has passed. Any thread currently blocked on a wait call will return. Note that multiple X_EVENT_WAKE events may be coalesced into one, and a wake event with an earlier timeout may cancel any wake event with a later timeout. This method is intended to be called from other threads and the relevant memory order semantics is memory_order_release on the calling thread and memory_order_acquire on the waiting thread.
static void x_event_queue_wake(x_event_queue_t* queue, uint64_t when);

// Destructs an event queue object, freeing all of its resources. It is invalid to call this while any thread is blocking on the queue.
static void x_event_queue_destroy(x_event_queue_t* q);

// Fills `data` with `len` bytes of high quality random bytes suitable for cryptographic purposes among many others.
static void x_randombytes(void* data, size_t len);