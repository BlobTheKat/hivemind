const log = txt => process.stdout.write('\x1b[2K\x1b[G\x1b[m' + txt)
log.nl = txt => process.stdout.write('\x1b[2K\x1b[G\x1b[m' + txt + '\n')

class Queue{
	latency = 25
	latencyJitter = 5
	latencyJitterSqueeze = 1
	loss = .0005
	_throughput = 3
	get throughput(){ return this._throughput }
	set throughput(a){ const diff = a/this._throughput; this._throughput = a; this._next = Math.floor(this._next * diff) }
	queue_sz_lo = 50
	queue_sz_ex = 10
	#sent = []
	_next = 0
	onMsg = null
	#pop = () => { const p = this.#sent.shift(); this.onMsg?.(p) }
	send(id){
		const now = Math.floor(performance.now() * this._throughput)
		const n = this._next-now
		if(n > this.queue_sz_lo){
			if(Math.random() < (n-this.queue_sz_lo)/this.queue_sz_ex)
				return
		}
		this._next = Math.max(this._next+1, now)
		if(Math.random() < this.loss) return
		this.#sent.push(id)
		setTimeout(this.#pop, this.latency + Math.max(0, n) / this.throughput + (Math.random() ** this.latencyJitterSqueeze) * this.latencyJitter)
	}
}
let arrays = {A: [], B: [], C: [], D: [], E: []}
let lost = 0, pts = 0, qd = 0, sent = 0
class Sender extends Queue{
	msPerMsg = 1
	sendWindow = 0
	int = 0; ackd = 0; xackd = []
	from = 0; to = 0
	minLatency = 50; minLatencyWhen = -10000
	avgLatency = 50
	growth = -1
	_start = 0
	_resends = 0
	_lastAck = 0
	rttGate = 0
	setReceiver(r = new Receiver()){
		this.onMsg = r.recvd; r.onMsg = this.recvd
		r.throughput = this.throughput*10
		this._start = performance.now()
		return this
	}
	recvd = id => {
		const now = performance.now()
		let sentAt = 0
		if(id == this.ackd){
			sentAt = this.xackd[0]
			let i = 1
			while(this.xackd[i] === 0) i++
			this.xackd = this.xackd.slice(i)
			this.ackd += i
			if(this.ackd == this.to){
				log.nl('\x1b[32mEverything ackd in '+(now-this._start).toFixed(2)+'ms, resend rate='+(this._resends/this.to*100).toFixed(2)+'%')
				this._start = now
				console.log(Object.keys(arrays).map(k => k+'=['+arrays[k].join(',')+']').join('\n\n'))
				process.exit()
			}
		}else{
			const i = id - this.ackd >>> 0
			if(i < this.xackd.length){
				sentAt = this.xackd[i]
				if(!sentAt) return
				this.xackd[i] = 0
			}else return
		}
		// Inverse packets per round trip, sanity-clamped
		const ipprt = Math.min(1, this.msPerMsg / this.minLatency)
		if(sentAt > 0){
			let lat = now - sentAt
			// Punish min_rtts measured more than 32 RTTs ago
			const rttsSinceMinLatency = (now-this.minLatencyWhen) / this.minLatency
			if(lat < this.minLatency * Math.max(1, rttsSinceMinLatency/32)){
				this.minLatency = lat
				this.minLatencyWhen = now
			}
			lat = (lat - this.avgLatency)*ipprt
			if(this.rttGate < 0){
				// queue fill signal
				qd += lat = lat>0 ? lat*2 : lat
				this.sendWindow += lat + (this.avgLatency-this.minLatency)*ipprt*.5
				let k = lat/(this.avgLatency-this.minLatency)
				this.growth -= k*.5
				this.growth = Math.min(-1, Math.max(-8, this.growth+.0625*ipprt))
				this.avgLatency += lat*.125
			}else{
				if(!this.rttGate) this.rttGate = this.from, this.avgLatency = now - sentAt
				else{
					this.avgLatency += lat
					if(id == this.rttGate) this.rttGate = -1
				}
			}
		}
		if(this._lastAck){
			this.msPerMsg += ((now-this._lastAck)*(1-2**this.growth) - this.msPerMsg)*ipprt*.5
		}
		this._lastAck = now
	}
	append(q = 10000){
		this.to += q
		this.int ||= setInterval(this._flush)
	}
	_lastLog = 0
	_flush = () => {
		const now = performance.now()
		let p = Math.max(this.sendWindow, now - (8 + this.msPerMsg))
		let msgs = Math.floor((now - p) / this.msPerMsg)
		if(now - this._lastLog > 20){
			this._lastLog += 20
			if(pts++ == 20){
				log.nl(`latency=${this.minLatency.toFixed(2)}ms+${(this.avgLatency-this.minLatency).toFixed(2)} throughput=${(1000/this.msPerMsg).toFixed(2)}/s g=${this.growth.toFixed(3)} lost=\x1b[31m${lost}\x1b[m qd=\x1b[33m${qd.toFixed(2)}ms\x1b[m`)
				lost = 0, pts = 0, qd = 0
			}
			arrays.A.push((1000/this.msPerMsg).toFixed(2))
			arrays.E.push(sent); sent = 0
			arrays.B.push((1/(1-2**this.growth)).toFixed(4))
			arrays.C.push(this.minLatency.toFixed(3))
			arrays.D.push(this.avgLatency.toFixed(3))
		}
		if(msgs <= 0) return
		let peak = now-this.avgLatency*2
		let resent = 0
		for(let i = 0; i < this.xackd.length; i++){
			const v = Math.abs(this.xackd[i])
			if(v){
				if(v >= peak) continue
				resent++; this._resends++
				this.xackd[i] = -now
				this.send(this.ackd+i)
				lost++
				if(resent == msgs) break
			}
		}
		this.sendWindow = p + msgs*this.msPerMsg
		msgs = Math.min(this.to - this.from, msgs - resent)
		sent += msgs + resent
		if(msgs){
			while(msgs--){
				if(!(this.from%50)) log('\x1b[33mSending ' + this.from)
				this.send(this.from++)
				this.xackd.push(now)
			}
			if(this.from == this.to)
				log.nl('\x1b[32mBuffer drained ('+(this.to-this.ackd)+' waiting)')
		}
	}
}

class Receiver extends Queue{
	constructor(){
		super()
		this.throughput *= 10
	}
	recvd = id => {
		this.send(id) // ack
	}
}

const to = new Sender()

to.setReceiver(new Receiver()).append(50000)

/* Dynamic bitrate test
setInterval(() => {
	const f = Math.sin(performance.now() * .0005)/3+1
	to.throughput = 3*f
	to.queue_sz_lo = 50*f
	to.queue_sz_ex = 10*f
	//log.nl('\x1b[35m=== Throughput changed ===')
}, 100) //*/