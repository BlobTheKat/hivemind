import { HivemindServer } from './src/node.js'
import { BufWriter, BufReader } from 'nanobuf'
import fs from 'fs/promises'

const server = new HivemindServer({
	key: await fs.readFile('../.master.key').catch(_e => {
		const key = crypto.getRandomValues(new Uint8Array(32))
		return fs.writeFile('../.master.key', key).then(() => key)
	}),
})
await server.listen(3331, '127.0.0.1')
console.log('\x1b[32mListening on :%d\x1b[m', server.address().port)

const pipe = server.createPipe(buf2 => {
	console.log('Got %d bytes', buf2.byteLength)
	buf2 = new Uint8Array(buf2)
	const buf = msgs.shift()
	if(!buf){
		console.log('Extra message!')
		return
	}
	if(buf2.length != buf.length){
		console.log("Lengths didn't match: %d != %d", buf.length, buf2.length)
		return
	}
	for(let i = 0; i < buf.length; i++){
		if(buf[i] != buf2[i]){
			console.log("Bytes didn't match: buf[%d] != buf2[%d]", i, i)
			return
		}
	}
	console.log('\x1b[32mPassed\x1b[m')
	if(!msgs.length){
		server.deletePipe(pipe)
		server.quit().then(() => {
			console.log('\x1b[35m=== All done ===\x1b[m')
		})
	}
})
console.log('pipe:', HivemindServer.pipeToString(pipe))

const msgs = []
function msg(len){
	const buf = new Uint8Array(len)
	for(let i = 0; i < len; i += 65536)
		crypto.getRandomValues(buf.subarray(i, i+65536))
	msgs.push(buf)
	server.send(pipe, buf)
}
for(let i = 9; i < 25; i++) msg(1<<i)
