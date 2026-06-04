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