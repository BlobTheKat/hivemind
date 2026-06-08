#include <hivemind.hpp>
#include <iostream>
using namespace hivemind;

void on_msg(HivemindServer<>* s, uint8_t* payload, size_t size, void* userdata){
	std::cout << "Got " << size << " bytes: " << std::string((char*)payload, size) << std::endl;
}


HivemindServer<> h_server { master_key_from_file("./.master.key"), on_msg };
int main(){
	h_server.start((remote_t){
		.addr = {0} /* [::] aka anywhere */, .port = 3331,
		.mtu = 0 /* unused */, .interface = 0 /* auto */,
	}, /*for address discovery*/ HIVEMIND_WAN_V4);

	// The pipe type is contiguous, trivially copyable and has a platform-independent binary representation.
	HivemindPipe pipe = h_server.create_pipe();

	// Potentially on another machine/instance
	const std::string data = "Hello, world!";
	h_server.send(pipe, data);
}