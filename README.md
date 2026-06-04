# <img src="./helipad512.png" alt="Helipad-style logo" width="64" style="vertical-align: middle; margin-right: 12px" /> **Hivemind**

**<u>East-west traffic. Safe. Fast. Reliable. No bloat.</u>**

For node bindings, jump to [Getting started (node.js)](#getting-started-nodejs)

## Building

Clang and `-flto` are preferred for performance.
```bash
clang -c hivemind_src/main.c -Iinclude -O3 -mcx16 -Wall -Wextra -Wno-unused -std=c11 -pthread -flto -o hivemind.o \
	&& ar rcs hivemind.a hivemind.o

# Linked with -flto -lhivemind
```

Supported platforms
- Linux
- FreeBSD, NetBSD, OpenBSD
- MacOS
- ~~Windows~~

## Getting started (C)

```c
#include <hivemind.h>

void load_master_key(uint8_t key[32], const char* filename){
	x_file_t fd = x_open(filename);
	if(x_getsize(fd) < 32){
		// Generate new key
		x_randombytes(key, 32);
		x_write(fd, 0, key, 32);
	}else{
		// Load existing key
		x_read(fd, 0, key, 32);
	}
	x_close(fd);
}

void on_msg(hivemind_server_t* s, uint8_t* payload, size_t size, void* userdata){
	printf("Got %zu bytes: %s", payload, size);
}

hivemind_server_t h_server;
int main(){
	uint8_t master_key[32];
	load_master_key(&master_key, "./.master.key");
	hivemind_init(&h_server, master_key, (hivemind_on_msg_fn_t) on_msg);

	hivemind_start(&h_server, (remote_t){
		.addr = {0} /* [::] aka anywhere */, .port = 3331,
		.mtu = 0 /* unused */, .interface = 0 /* auto */,
	}, /*for address discovery*/ HIVEMIND_WAN, /*state restoration*/ NULL, NULL);

	hivemind_pipe_t pipe;
	// The pipe type is contiguous, trivially copyable and has a platform-independent binary representation.
	hivemind_create_pipe(&h_server, &pipe, /*userdata*/ 0);

	// Potentially on another machine/instance
	const char* data = "Hello, world!";
	hivemind_send(&h_server, &pipe, &data, sizeof(data));
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