export default class HivemindServer{

	static pipeToString(pipe: ArrayBuffer): string
	static pipeFromString(pipeStr: string): ArrayBuffer

	constructor(options: {
		key: Uint8Array,
		maxPartition?: number,
		selfAddress?: string,
		selfPort?: number,
		selfMtu?: number /*,
		path?: string*/
	})
	address(): {address: string, port: number, family: "IPv4" | "IPv6"}

	readonly readyState: 0 | 1 | 2 | 3
	static readonly CLOSED: 0
	static readonly OPENING: 1
	static readonly OPEN: 2
	static readonly CLOSING: 3

	listen(port: number, host?: string, interface?: string, reflectionTest?: string): Promise<void>
	quit(): Promise<void>

	createPipe(onMsg: (buf: ArrayBuffer) => any): ArrayBuffer
	deletePipe(pipe: ArrayBuffer): void

	send(pipe: ArrayBuffer, msg: Uint8Array | ArrayBuffer | DataView): void
}