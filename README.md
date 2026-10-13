# <img src="./helipad512.png" alt="Helipad-style logo" width="64" style="vertical-align: middle; margin-right: 12px" /> **Hivemind**

### East-west traffic. [Safe](#safety-against-adversarial-network-participants). [Fast](#optimized-for-low-latency-and-high-throughput). [Reliable](#reliability-via-clean-failure-modes). [No bloat](#minimalism-by-design).

For node bindings, jump to [Getting started (node.js)](#getting-started-nodejs)

## Building

Clang and `-flto` are preferred for performance. Architecture-specific optimizations such as SSE are detected automatically and (usually) do not need flags.
```bash
clang -c src/main.c -Iinclude -O3 -mcx16 -Wall -Wextra -Wno-unused -std=c11 -pthread -flto -o hivemind.o \
	&& ar rcs hivemind.a hivemind.o

# Linked with -flto -lhivemind
```

Supported platforms
- Linux
- FreeBSD, NetBSD, OpenBSD
- MacOS
- ~~Windows~~ (Planned)

## Getting started (C)

```c
#include <hivemind.h>

void load_master_key(uint8_t key[32], const char* filename){
	x_file_t fd = x_open(filename, 0);
	if(x_getsize(fd) < 32){
		// Generate new key
		x_randombytes(key, 32);
		x_write(fd, key, 0, 32);
	}else{
		// Load existing key
		x_read(fd, key, 0, 32);
	}
	x_close(fd);
}

void on_msg(hivemind_server_t* s, void* userdata, uint8_t* payload, size_t size){
	printf("Got %zu bytes: %s", payload, size);
}

hivemind_server_t h_server;
int main(){
	uint8_t master_key[32];
	load_master_key(&master_key, "./.master.key");
	hivemind_init(&h_server, master_key, (hivemind_on_pipe_msg_fn_t) on_msg);

	hivemind_start(&h_server, (remote_t){
		.addr = {0} /* [::] aka anywhere */, .port = 3331,
		.mtu = 0 /* unused */, .interface = 0 /* auto */,
	}, /*for address discovery*/ HIVEMIND_WAN_V4, /*state restoration*/ NULL, NULL);

	hivemind_pipe_t pipe;
	// The pipe type is contiguous, trivially copyable and has a platform-independent binary representation.
	hivemind_create_pipe(&h_server, &pipe, /*userdata*/ NULL, HIVEMIND_QOS_REALTIME);

	// Potentially on another machine/instance
	const char* data = "Hello, world!";
	hivemind_send(&h_server, &pipe, &data, sizeof(data), NULL, 0);
}
```

## Getting started (node.js)

```js
import { HivemindServer } from 'hivemind-server'
import fs from 'fs/promises'

const hServer = new HivemindServer({
	key: await fs.readFile(process.env.MASTER_KEY_PATH)
})

await hServer.listen(/*port*/ 3331)
console.log('Listening on port %d', hServer.address().port)

function onMsg(msg: ArrayBuffer){
	console.log('Received: %s', new TextDecoder().decode(msg))
}

const pipe: ArrayBuffer = hServer.createPipe(onMsg)

// Potentially on another machine/instance
hServer.send(pipe, new TextEncoder().encode('Hello, world!'))
```

## Safety against adversarial network participants

On open networks, it is important to enforce data secrecy, integrity and authenticity, achieved using a cipher suite, in this case, ChaCha20-Poly1305. Endpoints not exposed to end-users should not create additional attack surfaces, of most immediate concern being denial-of-service attacks. Asymmetric key exchange algorithms (such as X25519) are slow and prone to deprecation as cryptanalysis advances. They are a necessary evil for north-south (client-server) traffic, but for east-west (server-server) traffic, simpler one-way key sharing is preferred. Hivemind uses a custom hashing construction based on ChaCha20 to derive a shared ephemeral secret from a pre-shared key, which is then used to encrypt and authenticate messages.

## Optimized for low latency and high throughput

The protocol is designed to minimize the number of round trips required to establish a connection and exchange data (see above). Under normal network conditions, time-to-first-byte for any message is limited only by the physical link latency (i.e 0.5RTT). The lack of bilateral key exchange step also means no cold starts for node pairs that have not recently exchanged messages. Packets are encoded tightly to reduce all but the absolutely necessary overhead.

Hivemind also offering options to bypass certain layers of abstraction given some assumptions about the network topology
- Encryption can be bypassed for recipients in the same closed network. Packet corruption is defended-against using CRC64 instead of Poly1305.
- IP/UDP can be bypassed when the recipient lives in the same broadcast domain (Layer 2).
- The entire network stack (and the kernel when under load) can be bypassed when the recipient lives on the same machine, via shared-memory IPC (Current implementation: [vqueue](https://github.com/BlobTheKat/vqueue)).
- Copy-less (pass-by-reference) when the recipient is in the same process.
All 5 modes of communication are completely transparent at the API level and can be used simultaneously, the protocol will automatically select the fastest available mode for a given recipient.

## Reliability via clean failure modes

Retransmission is handled automatically, however, relying on guaranteed eventual delivery is not a viable strategy for large scale systems with many nodes and independent failure points. Under some consistency models, synchronization at scale can also be a hard problem, especially when trying to avoid relying on a channel or resource after it has been reclaimed. Hivemind exposes a unified message delivery failure route to the application layer in a manner that does not increase complexity or require additional state management, and at negligible runtime overhead.

## Minimalism by design

