#include <sys/socket.h>
#include <stdint.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <memory.h>
#include "chacha20poly1305.h"
#include <unordered_set>
#include <shared_mutex>
#include <atomic>
#include "x.h"
#include <random>

struct hivemind{
	bool listen(remote_t where){
		
	}
	uint16_t weight = 4, flags = 0;
	remote_t self;
	struct node_t{
		uint32_t hash;
		remote_t remote;
		uint16_t weight;
	};
	size_t hashring_sizing = 0;
	std::atomic<node_t*> hashring_nodes;
	struct _hrh_entry{ uint32_t hash, id; };
	_hrh_entry** hashring_map = 0;
	void send(uint32_t hash, uint8_t* msg, size_t len){
		bool more;
		_hrh_entry* bucket = hashring_map[hash >> (hashring_sizing&31)];
		uint32_t l = bucket[0].hash;
		while(l--){
			if(bucket[1].hash > hash) break;
			bucket++;
		}
		node_t& n = hashring_nodes.load(std::memory_order::acquire)[bucket[0].id];
		
	}
};