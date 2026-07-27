export class HivemindServer{

	static pipeToString(pipe: ArrayBuffer): string
	static pipeFromString(pipeStr: string): ArrayBuffer

	constructor(options: {
		key: Uint8Array,
		maxPartition?: number,
		selfAddress?: string,
		selfPort?: number,
		selfMtu?: number,
		encryptionBypassPrefixV4?: number,
		encryptionBypassPrefixV6?: number,
		networkBypassPrefixV4?: number,
		networkBypassPrefixV6?: number,
	})
	address(): {address: string, port: number, family: "IPv4" | "IPv6"}

	readonly readyState: 0 | 1 | 2 | 3
	static readonly CLOSED: 0
	static readonly OPENING: 1
	static readonly OPEN: 2
	static readonly CLOSING: 3

	static readonly QOS_REALTIME: 0
	static readonly QOS_FASTER: 1
	static readonly QOS_SLOWER: 2
	static readonly QOS_BACKGROUND: 3

	listen(port: number, host?: string, interface?: string, options?: {
		reflectionTest?: string,
		path?: string,
		revive?: (buf: ArrayBuffer) => any | undefined
	}): Promise<void>
	quit(options?: {
		path?: string,
		save: (data: any) => ArrayBuffer
	}): Promise<void>

	createPipe(data: (buf: ArrayBuffer) => any | { onMsg: (buf: ArrayBuffer) => any }, qos: 0 | 1 | 2 | 3): ArrayBuffer
	deletePipe(pipe: ArrayBuffer): void

	send(pipe: ArrayBuffer, msg: Uint8Array | ArrayBuffer | DataView): void
}