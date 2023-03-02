#pragma once
//#include <vector>

#define DEFAULT_BACKLOG 128
#define SOCKS5_VERSION 5 
#define SOCKS_TYPE_OK 999

#define CLIENT_CONNECT_MAX 1024

#define ADDRESS_TYPE_IPV4 1
#define ADDRESS_TYPE_HOST 3
class Socks5Server;

static struct ClientStreamData {
	uv_tcp_t client_stream_tcp;
	uv_tcp_t tunnel_stream_tcp;
	unsigned int socks_type;
	unsigned int close_count;
};

static struct ThreadClientData {
	uv_loop_t client_loop_;
	uv_timer_t client_timer_;
	uv_thread_t thread_id;
	uv_async_t async_close_handle;
	uv_async_t async_wake_handle;

	Socks5Server* server;
	ClientStreamData* client_stream_data[CLIENT_CONNECT_MAX];
	
	//std::vector<ClientStreamData*> client_stream_data;

	unsigned int counts;
};



#pragma pack(1)

struct SocksMethodsResquest
{
	uint8_t ver;
	uint8_t nmethods;
	uint8_t methods[1];
};
struct SocksMethodResponse
{
	uint8_t ver;
	uint8_t method;
};
struct SocksCmdResquest
{
	uint8_t ver;
	uint8_t cmd;
	uint8_t rsv;
	uint8_t atyp;
	char dst_addr[1];
};

struct SocksCmdIpv4Resquest
{
	uint8_t ver;
	uint8_t cmd;
	uint8_t rsv;
	uint8_t atyp;
	uint32_t dst_addr;
	uint16_t dst_port;
};



struct SocksCmdIpv4Response
{
	uint8_t ver;
	uint8_t rep;
	uint8_t rsv;
	uint8_t atyp;
	uint32_t bnd_addr;
	uint16_t bnd_port;
};
#pragma pack()

class Socks5Server {

private:


	static void on_client_write(uv_write_t* req, int status) {
		if (status);
		if (req->write_buffer.base) {
			free(req->write_buffer.base);
		}
		free(req);
	}


	static void echo_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
		buf->base = reinterpret_cast<char*>(malloc(suggested_size));
		buf->len = suggested_size;
	}

	static void client_write_buf(uv_buf_t* write, const char* buf, const size_t size) {
		write->base = reinterpret_cast<char*>(malloc(size));; //reinterpret_cast<char*>(malloc(size));
		write->len = size;
		if (write->base != nullptr) {
			memcpy(write->base, buf, size);
		}
			
	}
	static void echo_client_read(uv_stream_t* client, ssize_t nread, const uv_buf_t* buf) {
		ClientStreamData* client_stream = reinterpret_cast<ClientStreamData*>(client->data);
		if (nread > 0) {
			uv_write_t* req = reinterpret_cast<uv_write_t*>(malloc(sizeof(uv_write_t)));
			if (req != nullptr) {
				req->write_buffer = uv_buf_init(buf->base, nread);
				uv_write(req, reinterpret_cast<uv_stream_t*>(&client_stream->tunnel_stream_tcp), &req->write_buffer, 1, on_client_write);
			}
			return;
		}
		else if (nread < 0) {
			if (nread != UV_EOF) {
				fprintf(stderr, "read error 1 %s\n", uv_err_name(nread));
			}

			uv_close(reinterpret_cast<uv_handle_t*>(&client_stream->client_stream_tcp), on_clinet_close);
			uv_close(reinterpret_cast<uv_handle_t*>(&client_stream->tunnel_stream_tcp), on_clinet_close);
		}
		if(buf->base)
			free(buf->base);
	}

	static void echo_client_readto(uv_stream_t* client, ssize_t nread, const uv_buf_t* buf) {
		ClientStreamData* client_stream = reinterpret_cast<ClientStreamData*>(client->data);
		if (nread > 0) {
			uv_write_t* req = reinterpret_cast<uv_write_t*>(malloc(sizeof(uv_write_t)));
			if (req != nullptr) {
				req->write_buffer = uv_buf_init(buf->base, nread);
				uv_write(req, reinterpret_cast<uv_stream_t*>(&client_stream->client_stream_tcp), &req->write_buffer, 1, on_client_write);
			}

			return;
		}
		else if (nread < 0) {
			if (nread != UV_EOF)
				fprintf(stderr, "read error 2 %s\n", uv_err_name(nread));

			uv_close(reinterpret_cast<uv_handle_t*>(&client_stream->client_stream_tcp), on_clinet_close);
			uv_close(reinterpret_cast<uv_handle_t*>(&client_stream->tunnel_stream_tcp), on_clinet_close);
		}
		if (buf->base)
			free(buf->base);
	}

	static void on_tunnel_connect(uv_connect_t* req, int status) {
		ClientStreamData* client_stream = reinterpret_cast<ClientStreamData*>(req->data);
		if (status) {
			uv_close(reinterpret_cast<uv_handle_t*>(&client_stream->client_stream_tcp), on_clinet_close);
			uv_close(reinterpret_cast<uv_handle_t*>(&client_stream->tunnel_stream_tcp), on_clinet_close);
			free(req);
			return;
		}
		//uv_tcp_keepalive(&client_stream->client_stream_tcp, 1, 10);
		//uv_tcp_keepalive(&client_stream->tunnel_stream_tcp, 1, 10);

		uv_read_start(reinterpret_cast<uv_stream_t*>(&client_stream->client_stream_tcp), echo_alloc, echo_client_read);
		uv_read_start(reinterpret_cast<uv_stream_t*>(&client_stream->tunnel_stream_tcp), echo_alloc, echo_client_readto);

		free(req);
	}



	static void get_host_ip(const char* domain, char* ip) {
		struct hostent* host = gethostbyname(domain);
		if (host == NULL)
			return;
		for (int i = 0; host->h_addr_list[i]; i++) {
			strcpy(ip, inet_ntoa(*(struct in_addr*)host->h_addr_list[i]));
			break;
		}
	}

	static bool check_socks_verify(char* buf, const size_t size, uv_buf_t* write, ClientStreamData* clinet_stream) {
		if (clinet_stream->socks_type == 0) {
			SocksMethodsResquest* resquest = reinterpret_cast<SocksMethodsResquest*>(buf);
			if (resquest->ver != SOCKS5_VERSION) return false;
			SocksMethodResponse response;
			response.ver = SOCKS5_VERSION;
			response.method = 0;
			client_write_buf(write, reinterpret_cast<char*>(&response), sizeof(response));
			++clinet_stream->socks_type;
			return true;
		}
		else if (clinet_stream->socks_type == 1) {

			SocksCmdResquest* cmd = reinterpret_cast<SocksCmdResquest*>(buf);
			if (size < sizeof(SocksCmdResquest)) return false;
			sockaddr_in client_addr;

			if (cmd->atyp == ADDRESS_TYPE_IPV4 && size == sizeof(SocksCmdIpv4Resquest)) {
				SocksCmdIpv4Resquest* cmdv4 = reinterpret_cast<SocksCmdIpv4Resquest*>(buf);
				uint32_t dest_addr = cmdv4->dst_addr;
				uint16_t dest_port = cmdv4->dst_port;
				client_addr.sin_addr.S_un.S_addr = dest_addr;
				client_addr.sin_port = dest_port;
				client_addr.sin_family = AF_INET;
			}
			else if (cmd->atyp == ADDRESS_TYPE_HOST)  {
				uint8_t len = cmd->dst_addr[0];
				char host_str[100] = { 0x0 };
				memcpy(host_str, buf + sizeof(SocksCmdResquest), len);
				char ip_str[30] = { 0x0 };
				get_host_ip(host_str, ip_str);

				uint16_t dest_port = *reinterpret_cast<unsigned short*>(cmd->dst_addr + 1 + len);
				dest_port = ntohs(dest_port);
				int r = uv_ip4_addr(ip_str, dest_port, &client_addr);
			}
			else {
				return false;
			}
			SocksCmdIpv4Response response;
			response.ver = SOCKS5_VERSION;
			response.rep = 0;
			response.rsv = 0;
			response.atyp = 1;
			response.bnd_addr = 0;
			response.bnd_port = 0;
			uv_connect_t* connect = reinterpret_cast<uv_connect_t*>(malloc(sizeof(uv_connect_t)));
			
			connect->data = clinet_stream;


			int r = uv_tcp_connect(connect, &clinet_stream->tunnel_stream_tcp, reinterpret_cast<sockaddr*>(&client_addr), on_tunnel_connect);
			if (r) {
				response.atyp = 0;
			}
			uv_read_stop(reinterpret_cast<uv_stream_t*>(&clinet_stream->client_stream_tcp));
			client_write_buf(write, reinterpret_cast<char*>(&response), sizeof(response));
			clinet_stream->socks_type = SOCKS_TYPE_OK;
			return true;
		}
		return false;
	}



	static void on_clinet_close(uv_handle_t* handle) {

		if (handle->data) {
			ClientStreamData *client_stream_data = reinterpret_cast<ClientStreamData*>(handle->data);
			client_stream_data->close_count++;
		}

	}

	static void echo_socks_read_buf(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
		ClientStreamData* data = reinterpret_cast<ClientStreamData*>(stream->data);
		if (nread > 0) {
			uv_write_t* req = reinterpret_cast<uv_write_t*>(malloc(sizeof(uv_write_t)));
			if (check_socks_verify(buf->base, nread, &req->write_buffer, data)) {
				uv_write(req, stream, &req->write_buffer, 1, on_client_write);
				if (buf->base)
					free(buf->base);
				return;
			}
			free(req);
			if(buf->base)
				free(buf->base);
		}
		else if(nread < 0) {
			if (nread != UV_EOF)
				 fprintf(stderr, "read 0 error %s\n", uv_err_name(nread));

			//if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(stream))) 
			uv_close(reinterpret_cast<uv_handle_t*>(stream), on_clinet_close);
			uv_close(reinterpret_cast<uv_handle_t*>(&data->tunnel_stream_tcp), on_clinet_close);

			if (buf->base)
				free(buf->base);
		}
	}

	static void on_new_connection(uv_stream_t* server, int status) {
		int r = 0;
		if (status) {
				uv_close(reinterpret_cast<uv_handle_t*>(server), [](uv_handle_t* handle) {
						
				});
				return ;
		}
		Socks5Server* _server = reinterpret_cast<Socks5Server*>(server->data);
		ThreadClientData* thread_client_data =_server->get_clinet_loop();
		if (thread_client_data->counts > CLIENT_CONNECT_MAX) return ;
		
		ClientStreamData* client_stream_data = reinterpret_cast<ClientStreamData*>(malloc(sizeof(ClientStreamData)));//reinterpret_cast<ClientStreamData*> (malloc(sizeof(ClientStreamData)));
		thread_client_data->counts++;
		for (size_t i = 0; i < CLIENT_CONNECT_MAX; i++) {
			if (thread_client_data->client_stream_data[i] == nullptr) {
				thread_client_data->client_stream_data[i] = client_stream_data;
				break;
			}
		}



		if (client_stream_data != nullptr) {
			memset(client_stream_data, 0, sizeof(ClientStreamData));
			client_stream_data->client_stream_tcp.data = client_stream_data;
			client_stream_data->tunnel_stream_tcp.data = client_stream_data;
		}
		else {
			return ;
		}


		uv_tcp_init(&thread_client_data->client_loop_, &client_stream_data->tunnel_stream_tcp);
		uv_tcp_init(&thread_client_data->client_loop_, &client_stream_data->client_stream_tcp);
		if (uv_accept(server, reinterpret_cast<uv_stream_t*>(&client_stream_data->client_stream_tcp)) == 0) {
			uv_async_send(&thread_client_data->async_wake_handle);
			r = uv_read_start(reinterpret_cast<uv_stream_t*>(&client_stream_data->client_stream_tcp), echo_alloc, echo_socks_read_buf);
		}
		

	}

public: 
	Socks5Server() : server_loop_(uv_default_loop()), isclosed_(FALSE), thread_number_(2), clinet_index_(0){};
	~Socks5Server() {};


	void init_clinet_thread() {
		thread_client_ = reinterpret_cast<ThreadClientData*>(malloc(sizeof(ThreadClientData) * thread_number_));
	
		memset(thread_client_, 0, sizeof(ThreadClientData) * thread_number_);

		
		for (size_t i = 0; i < thread_number_; i++) {
			uv_loop_init(&thread_client_[i].client_loop_);
			thread_client_[i].server = this;
			thread_client_[i].async_close_handle.data = &thread_client_[i];

			uv_async_init(&thread_client_[i].client_loop_, &thread_client_[i].async_close_handle, [](uv_async_t* handle){
				ThreadClientData* thread_client_data = reinterpret_cast<ThreadClientData*>(handle->data);

				thread_client_data->client_loop_.data = thread_client_data;
		

				thread_client_data->server->on_thread_clinet_close(&thread_client_data->client_loop_);
			});

			uv_async_init(&thread_client_[i].client_loop_, &thread_client_[i].async_wake_handle, [](uv_async_t* handle) {

			});

			uv_timer_init(&thread_client_[i].client_loop_, &thread_client_[i].client_timer_);

			thread_client_[i].client_timer_.data = &thread_client_[i];
			uv_timer_start(&thread_client_[i].client_timer_, [](uv_timer_t* handle) {
				ThreadClientData* thread_client_data = reinterpret_cast<ThreadClientData*>(handle->data);

				for (size_t i = 0; i < CLIENT_CONNECT_MAX && thread_client_data->counts; i++) {
					ClientStreamData* clinet_stream_data = thread_client_data->client_stream_data[i];
					if (clinet_stream_data == nullptr) continue;
					if (clinet_stream_data->close_count == 2) {
						free(clinet_stream_data);
						thread_client_data->client_stream_data[i] = nullptr;
						thread_client_data->counts--;
					}


				}


			}, 1000, 4000);

			uv_thread_create(&thread_client_[i].thread_id, [](void* arg) {
				ThreadClientData* thread_client = reinterpret_cast<ThreadClientData*>(arg);
				uv_run(&thread_client->client_loop_, UV_RUN_DEFAULT);
				
				uv_loop_close(&thread_client->client_loop_);
				
			}, &thread_client_[i]);
		}
	}

	ThreadClientData* get_clinet_loop() {
		return &thread_client_[clinet_index_++ % thread_number_];
	}
	int listen(unsigned short port) {
		sockaddr_in server_addr;
		int r = 0;

		init_clinet_thread();

		server_close_handle_.data = this;
		uv_async_init(server_loop_, &server_close_handle_, [](uv_async_t* handle) {
			Socks5Server* server = reinterpret_cast<Socks5Server*>( handle->data);
			server->on_server_close();
		});

		

		r = uv_ip4_addr("0.0.0.0", port, &server_addr);
		r = uv_tcp_init(server_loop_, &server_tcp_);

		r = uv_tcp_bind(&server_tcp_, reinterpret_cast<sockaddr*>(&server_addr), 0);
		if (r != 0) return r;
		server_tcp_.data = this;
		r = uv_listen(reinterpret_cast<uv_stream_t*>(&server_tcp_), DEFAULT_BACKLOG, on_new_connection);
		if (r != 0) return r;
		uv_thread_create(&server_thread_handle_, [](void* arg) {
			uv_run(uv_default_loop(), UV_RUN_DEFAULT);
			uv_loop_close(uv_default_loop());
		}, this);
		return 0;
	}
	static void on_close_walk(uv_handle_t* handle, void* arg) {
		if (!uv_is_closing(handle)) {
			uv_close(handle, [](uv_handle_t* handle) {
				

			});
		}
	}
	void on_thread_clinet_close(uv_loop_t* loop) {
		if (!isclosed_) return;
		uv_stop(loop);
		ThreadClientData* thread_client_data = reinterpret_cast<ThreadClientData*>(loop->data);
		if (thread_client_data == nullptr) return;
		for (size_t i = 0; i < CLIENT_CONNECT_MAX && thread_client_data->counts; i++) {
			ClientStreamData* clinet_stream_data = thread_client_data->client_stream_data[i];
			if (clinet_stream_data == nullptr) continue;

			if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(&clinet_stream_data->client_stream_tcp))) {
				uv_close(reinterpret_cast<uv_handle_t*>(&clinet_stream_data->client_stream_tcp), [](uv_handle_t* handle) {

				});
			}

			if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(&clinet_stream_data->tunnel_stream_tcp))) {
				uv_close(reinterpret_cast<uv_handle_t*>(&clinet_stream_data->tunnel_stream_tcp), [](uv_handle_t* handle) {

				});
			}
			free(clinet_stream_data);
			thread_client_data->client_stream_data[i] = nullptr;
			thread_client_data->counts--;

		}


		uv_walk(loop, on_close_walk, this);//close all handle in loop
	}
	void on_server_close() {
		if (!isclosed_) return;
		uv_walk(uv_default_loop(), on_close_walk, this);//close all handle in loop
	}
	void close() {
		isclosed_ = true;
		uv_async_send(&server_close_handle_);
		for (size_t i = 0; i < thread_number_; i++) {
			uv_async_send(&thread_client_[i].async_close_handle);
		}
	}
	void join() {
		uv_thread_join(&server_thread_handle_);		
		for (size_t i = 0; i < thread_number_; i++) {
			uv_thread_join(&thread_client_[i].thread_id);
		}
		free(thread_client_);
	}
private:
	uv_loop_t* server_loop_;
	uv_thread_t server_thread_handle_;
	uv_async_t server_close_handle_;
	uv_tcp_t server_tcp_;

	bool isclosed_;
	unsigned int thread_number_;
	ThreadClientData* thread_client_;
	unsigned int clinet_index_;
};