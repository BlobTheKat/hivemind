# Hivemind Node.js Bindings

Native Node.js bindings for the Hivemind high-performance networking library.

## Installation

First, ensure you have proper build tools and git installed:

```sh
# macOS (Xcode), comes with git
xcode-select --install

# Linux (Ubuntu/Debian) via LLVM
sudo apt-get install git clang lld
# or
sudo apt-get install git build-essential

# Windows via Scoop's LLVM. Hivemind MSVC support is rudimentary.
# Learn more about scoop and how to install it here: https://scoop.sh/
scoop install llvm git
```

Then installation should be seamless

```sh
npm install --save hivemind-server

# You can also override certain build parameters, e.g
# CC=/my/gcc CXX=/my/g++ EXTRA_FLAGS="-fuse-ld=/my/ld -Werror" npm install --save hivemind-server
```



## Quick Start

```js
import { HivemindServer } from 'hivemind-server'
import fs from 'fs'

const server = new HivemindServer({
	key: fs.readFileSync('../.master.key'),
})
await server.listen(3331)
console.log('Listening on port %d', server.address().port)

function onMsg(arrBuf){
	console.log('Received: %s', new TextDecoder().decode(arrBuf))
	server.quit()
}

const pipe = server.createPipe(onMsg)

// Potentially on another machine/instance
server.send(pipe, new TextEncoder().encode('Hello, world!'))
```