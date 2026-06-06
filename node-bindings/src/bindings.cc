#include <dbg.h>
#include <uv.h>
#include <cstring>
#include <cstdlib>
#include <atomic>
#include "utils.hh"
#include <hivemind.h>

#define SECOND_US 1000000

class HivemindServerJS : public Napi::ObjectWrap<HivemindServerJS>{
	enum class State{ CLOSED = 0, OPENING = 2, OPENING_READY = 3, OPEN = 4, CLOSING = 6, CLOSING_READY = 7 };
	struct PipeMeta{
		Napi::FunctionReference cb;
		std::atomic<size_t> ref;
	};
	struct Msg{
		PipeMeta* m;
		uint8_t* data; size_t size;
	};
	static void on_msg(HivemindServerJS* s, const uint8_t* payload, size_t size, void* udata){
		PipeMeta* m = static_cast<PipeMeta*>(udata);
		m->ref.fetch_add(1, std::memory_order::relaxed);
		s->msg_lock.lock();
		hivemind_pipe_unlock();
		s->msgs.push_back({m, hivemind_packet_detach(payload), size});
		s->msg_lock.unlock();
		uv_async_send(&s->async_handle);
	}
	static void async_cb(uv_async_t* handle){
		HivemindServerJS* s = (HivemindServerJS*) handle->data;
		s->msg_lock.lock();
		auto v = std::move(s->msgs);
		State state = s->state;
		s->msg_lock.unlock();
		Napi::HandleScope _(s->Env());
		if(state == State::OPENING_READY){
			s->state = State::OPEN;
			s->on_open_close->Resolve(s->Env().Undefined());
			s->on_open_close.destruct();
			s->Unref();
		}
		for(auto& item : v){
			if(!item.m->cb.IsEmpty()){
				auto v = Napi::ArrayBuffer::New(s->Env(), item.data, item.size);
				item.m->cb.Value().Call({v});
				v.Detach();
			}
			if(item.m->ref.fetch_sub(1, std::memory_order::release) == 1) delete item.m;
			hivemind_packet_free(item.data);
		}
		if(state == State::CLOSING_READY){
			s->state = State::CLOSED;
			uv_unref((uv_handle_t*)&s->async_handle);
			s->on_open_close->Resolve(s->Env().Undefined());
			s->on_open_close.destruct();
			s->Unref();
		}
	}
	static void on_done(HivemindServerJS* s){
		s->msg_lock.lock();
		s->state = State::CLOSING_READY;
		s->msg_lock.unlock();
		uv_async_send(&s->async_handle);
	}
	static void free_pipe(HivemindServerJS* s, PipeMeta* p){
		delete p;
	}
	static Napi::Value PipeToString(const Napi::CallbackInfo& info){
		if(info.Length() != 1 || !info[0].IsArrayBuffer()) err: {
			Napi::TypeError::New(info.Env(), "Failed to execute 'pipeToString': First argument must be an ArrayBuffer of length 40").ThrowAsJavaScriptException();
			return info.Env().Undefined();
		}
		auto pipev = info[0].As<Napi::ArrayBuffer>();
		if(pipev.ByteLength() < sizeof(hivemind_pipe_t)) goto err;
		hivemind_pipe_t pipe;
		memcpy(&pipe, pipev.Data(), sizeof(hivemind_pipe_t));
		char out[HIVEMIND_PIPE_STR_MAX_LEN];
		hivemind_pipe_to_string(&pipe, out);
		return Napi::String::New(info.Env(), out);
	}
	static Napi::Value PipeFromString(const Napi::CallbackInfo& info){
		if(info.Length() != 1 || !info[0].IsString()) err: {
			Napi::TypeError::New(info.Env(), "Failed to execute 'pipeFromString': First argument must be a string").ThrowAsJavaScriptException();
			return info.Env().Undefined();
		}
		auto pipev = Napi::ArrayBuffer::New(info.Env(), sizeof(hivemind_pipe_t));
		if(!hivemind_pipe_from_string((hivemind_pipe_t*) pipev.Data(), info[0].As<Napi::String>().Utf8Value().c_str())) return info.Env().Null();
		return pipev;
	}

	static Napi::Function GetClass(Napi::Env env){
		return DefineClass(env, "HivemindServerJS", {
			StaticMethod("pipeToString", &HivemindServerJS::PipeToString),
			StaticMethod("pipeFromString", &HivemindServerJS::PipeFromString),
			InstanceMethod("listen", &HivemindServerJS::listen),
			InstanceMethod("createPipe", &HivemindServerJS::CreatePipe),
			InstanceMethod("deletePipe", &HivemindServerJS::DeletePipe),
			InstanceMethod("send", &HivemindServerJS::Send),
			InstanceMethod("quit", &HivemindServerJS::Quit),
			InstanceMethod("address", &HivemindServerJS::GetBoundAddress),
			InstanceAccessor("readyState", &HivemindServerJS::GetReadyState, 0),
			StaticValue("CLOSED", Napi::Number::New(env, (int)State::CLOSED>>1)),
			StaticValue("OPENING", Napi::Number::New(env, (int)State::OPENING>>1)),
			StaticValue("OPEN", Napi::Number::New(env, (int)State::OPEN>>1)),
			StaticValue("CLOSING", Napi::Number::New(env, (int)State::CLOSING>>1)),
		});
	}
	std::mutex msg_lock;
	State state = State::CLOSED;
	std::vector<Msg> msgs;
	uv_async_t async_handle;
	Napi::AsyncContext async_context;
	slot<Napi::Promise::Deferred> on_open_close;
	hivemind_server_t server_;
	public:
	HivemindServerJS(const Napi::CallbackInfo& info) : Napi::ObjectWrap<HivemindServerJS>(info), async_context(info.Env(), "Hivemind"){
		auto env = info.Env();
		if(info.Length() != 1 || !info[0].IsObject()) {
			Napi::TypeError::New(env, "Failed to construct 'HivemindServer': First and only argument must be an object").ThrowAsJavaScriptException();
		}
		auto props = info[0].As<Napi::Object>();
		auto keyv = props.Get("key");
		if(!keyv.IsTypedArray()) key_err: {
			Napi::TypeError::New(env, "Failed to construct 'HivemindServer': property 'key' is not a TypedArray of at least 32 bytes").ThrowAsJavaScriptException();
		}
		auto key = keyv.As<Napi::Uint8Array>();
		if(key.ByteLength() < 32) goto key_err;

		hivemind_init(&server_, key.Data(), (hivemind_on_msg_fn_t) HivemindServerJS::on_msg);

		server_.udata = this;
		auto partv = props.Get("maxPartition");
		if(partv.IsNumber()){
			double v = partv.As<Napi::Number>().DoubleValue()*1000.;
			// sane minimum 5min
			if(v < 0 || v >= (double)UINT64_MAX) server_.state_lifetime = UINT64_MAX;
			else if(v < 300*SECOND_US) server_.state_lifetime = 300*SECOND_US;
			else server_.state_lifetime = v;
		}

		auto addrv = props.Get("selfAddress");
		if(addrv.IsString()){
			char str[IP_STR_MAX_LEN];
			Napi_utf8_copy(addrv.As<Napi::String>(), str, IP_STR_MAX_LEN);
			server_.addr = ip_from_string(str);
		}
		auto portv = props.Get("selfPort");
		if(portv.IsNumber()){
			int port = portv.As<Napi::Number>().Uint32Value();
			server_.port_lo = port;
			server_.port_hi = port>>8;
		}
		auto mtuv = props.Get("selfMtu");
		if(mtuv.IsNumber()){
			int mtu = mtuv.As<Napi::Number>().Uint32Value();
			if(mtu > 65535) mtu = 65535;
			server_.mtu_lo = mtu;
			server_.mtu_hi = mtu>>8;
		}
	}
	Napi::Value listen(const Napi::CallbackInfo& info){
		if(this->state != State::CLOSED){
			Napi::Error::New(info.Env(), "Failed to execute 'listen' on 'HivemindServer': The server is already running").ThrowAsJavaScriptException();
			return info.Env().Undefined();
		}
		int argc = info.Length();
		if(argc < 1 || !info[0].IsNumber()){
			Napi::TypeError::New(info.Env(), "Failed to execute 'listen' on 'HivemindServer': first argument must be a valid port number").ThrowAsJavaScriptException();
			return info.Env().Undefined();
		}
		remote_t r;
		r.port = (uint16_t) info[0].As<Napi::Number>().Uint32Value();
		ip_addr_t test = HIVEMIND_WAN;
		if(argc >= 2){
			if(info[1].IsString()){
				char str[IP_STR_MAX_LEN];
				Napi_utf8_copy(info[1].As<Napi::String>(), str, IP_STR_MAX_LEN);
				r.addr = ip_from_string(str);
			}
			if(argc >= 3){
				if(info[2].IsString())
					r.interface = interface_from_str(info[2].As<Napi::String>().Utf8Value().c_str());
				if(argc >= 4 && info[3].IsString()){
					char str[IP_STR_MAX_LEN];
					Napi_utf8_copy(info[3].As<Napi::String>(), str, IP_STR_MAX_LEN);
					test = ip_from_string(str);
				}
			}
		}
		// ref
		uv_loop_s* loop;
		int err;
		err = napi_get_uv_event_loop(info.Env(), &loop);
		assert(err == 0, "napi_get_uv_event_loop");
		err = uv_async_init(loop, &async_handle, async_cb);
		async_handle.data = this;
		assert(err == 0, "uv_async_init");
		if(!hivemind_start(&server_, r, test, 0, 0)){
			uv_unref((uv_handle_t*)&async_handle);
			Napi::Error::New(info.Env(), "Failed to execute 'listen' on 'HivemindServerJS': could not bind to address").ThrowAsJavaScriptException();
			return info.Env().Undefined();
		}
		this->state = State::OPEN;
		this->Ref();
		auto def = Napi::Promise::Deferred::New(info.Env());
		def.Resolve(info.Env().Undefined());
		return def.Promise();
	}

	HivemindServerJS(HivemindServerJS&&) = delete;
	HivemindServerJS& operator=(HivemindServerJS&&) = delete;
	HivemindServerJS(const HivemindServerJS&) = delete;
	HivemindServerJS& operator=(const HivemindServerJS&) = delete;

	Napi::Value CreatePipe(const Napi::CallbackInfo& info) {
		if(info.Length() < 1 || !info[0].IsFunction()){
			Napi::TypeError::New(info.Env(), "Failed to execute 'createPipe' on 'HivemindServer': First argument must be a function").ThrowAsJavaScriptException();
			return info.Env().Undefined();
		}
		auto ref = new PipeMeta{ Napi::Persistent(info[0].As<Napi::Function>()), 1 };
		auto buf = Napi::ArrayBuffer::New(info.Env(), sizeof(hivemind_pipe_t));
		hivemind_create_pipe(&server_, (hivemind_pipe_t*) buf.Data(), ref);
		return buf;
	}
	Napi::Value GetReadyState(const Napi::CallbackInfo& info){
		return Napi::Number::New(info.Env(), (int)this->state>>1);
	}
	Napi::Value DeletePipe(const Napi::CallbackInfo& info) {
		if(info.Length() < 1 || !info[0].IsArrayBuffer()) err: {
			Napi::TypeError::New(info.Env(), "Failed to execute 'deletePipe' on 'HivemindServer': First argument must be an ArrayBuffer of length 40").ThrowAsJavaScriptException();
			return info.Env().Undefined();
		}
		auto pipev = info[0].As<Napi::ArrayBuffer>();
		if(pipev.ByteLength() < sizeof(hivemind_pipe_t)) goto err;
		hivemind_pipe_t pipe;
		memcpy(&pipe, pipev.Data(), sizeof(hivemind_pipe_t));
		PipeMeta* m = (PipeMeta*) hivemind_close_pipe(&server_, &pipe);
		m->cb.Unref();
		if(m->ref.fetch_sub(1, std::memory_order::release) == 1) delete m;
		return info.Env().Undefined();
	}

	Napi::Value GetBoundAddress(const Napi::CallbackInfo& info){
		char out[IP_STR_MAX_LEN];
		enum ip_kind kind = ip_to_string(server_.addr, out);
		auto ret = Napi::Object::New(info.Env());
		ret.Set("address", Napi::String::New(info.Env(), out));
		ret.Set("port", Napi::Number::New(info.Env(), server_.port_lo|server_.port_hi<<8));
		char family[] = "IPv6";
		if(kind == IP_KIND_V4) family[3] = '4';
		ret.Set("family", Napi::String::New(info.Env(), family));
		return ret;
	}

	Napi::Value Send(const Napi::CallbackInfo& info) {
		Napi::Env env = info.Env();

		if (info.Length() < 2 || !info[0].IsArrayBuffer()) type_err: {
			Napi::TypeError::New(info.Env(), "Failed to execute 'send' on 'HivemindServer': First argument must be an ArrayBuffer of length 40. Second argument must be an ArrayBufferView").ThrowAsJavaScriptException();
			return info.Env().Undefined();
		}
		auto tov = info[0].As<Napi::ArrayBuffer>();
		if(tov.ByteLength() < 40) goto type_err;
		void* data; size_t sz;
		if(info[1].IsTypedArray()){
			auto v = info[1].As<Napi::TypedArrayOf<uint8_t>>();
			data = v.Data(); sz = v.ByteLength();
		}else if(info[1].IsArrayBuffer()){
			auto v = info[1].As<Napi::ArrayBuffer>();
			data = v.Data(); sz = v.ByteLength();
		}else if(info[1].IsDataView()){
			auto v = info[1].As<Napi::ArrayBuffer>();
			data = v.Data(); sz = v.ByteLength();
		}else goto type_err;
		hivemind_pipe_t to;
		memcpy(&to, tov.Data(), sizeof(to));
		// Sanity check: V8 aligns ArrayBuffer contents to at least 4 (alignof(hivemind_pipe_t)) because Uint32Arrays exist and they won't be fast without that
		hivemind_send(&server_, &to, (uint8_t*) data, sz);

		return env.Undefined();
	}

	Napi::Value Quit(const Napi::CallbackInfo& info) {
		if(this->state != State::OPEN){
			Napi::Error::New(info.Env(), "Failed to execute 'quit' on 'HivemindServer': The server is not running").ThrowAsJavaScriptException();
			return info.Env().Undefined();
		}
		this->state = State::CLOSING;
		hivemind_quit(&server_, (hivemind_generic_fn_t) HivemindServerJS::on_done, 0, (hivemind_pipe_finish_fn_t) HivemindServerJS::free_pipe);
		// Beyond this part it is not possible to receive more messages
		on_open_close.construct(Napi::Promise::Deferred::New(info.Env()));
		return on_open_close->Promise();
	}
	~HivemindServerJS(){
		x_zerobytes(&server_, sizeof(server_));
	}
	friend Napi::Object Init(Napi::Env env, Napi::Object exports);
};

Napi::Object Init(Napi::Env env, Napi::Object exports){
  return HivemindServerJS::GetClass(env);
}

NODE_API_MODULE(hivemind, Init)