#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <glib.h>
#include <glib/gprintf.h>
#include <pthread.h>
#include <errno.h>

#include "prefetch_dma.h"

#define DEV_NAME "/dev/mmap"
#define TRANSFER_SIZE 64

struct transfer_data_to_user {
	uint64_t addr;
	char buf[PAGE_SIZE];
};
GHashTable *hash;

struct doca_pci_bdf pcie_addr;
struct app_state send_state, recv_state;
struct app_state send_doorbell_state, recv_doorbell_state;
struct doca_state d_state, d_cli_state;
struct doca_state d_send_doorbell_state, d_recv_doorbell_state;

/************************/
char *receiver_ip;
uint16_t receiver_port;
char *port;

int sender_fd;
int mapped_fd;

pthread_t send_thread;
pthread_t recv_thread;

bool recv_thread_state = true, send_thread_state = true;
uint8_t recv_doorbell, send_doorbell;
typedef enum ROLE {
	SERVER = 0,
	CLIENT
} ROLE;
typedef enum MODE {
	SEND = 0,
	RECV
} MODE;
/************************/

struct prefetch_user_config prefetch_user_config = {0};

/************************/
int hash_table_size;
int h_dma_send_state;
extern int errno;
/***********************/

DOCA_LOG_REGISTER(DOCA_DMA);

bool printLog(doca_error_t res) 
{
	if(res != DOCA_SUCCESS) {
		DOCA_LOG_ERR("err = %s", doca_get_error_string(res));
		return false;
	}
	return true;
}

void make_server_thread(struct app_state *state, struct doca_state *d_state, struct hash_data *data, size_t data_to_copy_len, MODE mode)
{
	struct thread_data tdata = {
		.mapped_fd = mapped_fd,
		.state = state,
		.buffer = data,
		.data_to_copy_len = data_to_copy_len,
		.d_state = d_state
	};
	if(mode == SEND) pthread_create(&send_thread, NULL, server_send, (void *)&tdata);
	else pthread_create(&recv_thread, NULL, server_recv, (void *)&tdata);
}

void make_client_thread(struct app_state *state, struct hash_data *data, size_t data_to_copy_len, MODE mode)
{
	struct thread_data tdata = {
		.mapped_fd = mapped_fd,
		.state = state,
		.buffer = data,
		.data_to_copy_len = data_to_copy_len,
		.d_state = NULL
	};
	if(mode == SEND) pthread_create(&send_thread, NULL, client_send, (void *)&tdata);
	else pthread_create(&recv_thread, NULL, client_recv, (void *)&tdata);
}
/*
void free_gdata(gpointer data)
{
	g_free(data);
}

void free_data(gpointer data)
{
	free(data);
}

void init_hash_table(void)
{
	hash = g_hash_table_new_full(g_int64_hash, g_int64_equal, free_gdata, free_data); 
}

void hash_table_insert(struct transfer_data_to_user data) 
{
	struct hash_data *hdata = (struct hash_data *)malloc(sizeof(struct hash_data));
	gint64 *key = g_new(gint64, data.addr);

	gpointer gp = g_hash_table_lookup(hash, key);
	if(gp == NULL) hash_table_size++;
	
	memcpy(hdata, &data, sizeof(struct hash_data));
	g_hash_table_insert(hash, key, hdata);
}

void h_dma_send(gpointer key, gpointer value,  gpointer user_data)
{
	struct hash_data *data = (struct hash_data *)value;
	doca_error_t res;
	res = dma_remote_copy_sender(send_state, data, sizeof(struct hash_data), sender_fd);
	if (res != DOCA_SUCCESS) {
		DOCA_LOG_ERR("dma_remote_copy_sender error = %s", doca_get_error_string(res));
	} 
	else 
		h_dma_send_state++;
}

doca_error_t
dma_send(struct hash_data *src_buffer) {
	return dma_remote_copy_sender(send_state, src_buffer, sizeof(*src_buffer), sender_fd);
}

doca_error_t
dma_metadata_send(uint64_t addr)
{
	struct hash_data src_buffer;
	src_buffer.addr = addr;
	memset(&src_buffer.buf, '\0', sizeof(src_buffer.buf));
	return dma_remote_copy_sender(send_state, &src_buffer, sizeof(src_buffer), sender_fd);
}

doca_error_t
dma_recv(struct hash_data *dst_buffer) 
{
	return dma_remote_copy_receiver(recv_state, dst_buffer, sizeof(struct hash_data), sender_fd);
}

void* doca_recv(void *arg) 
{
	DOCA_LOG_INFO("doca send start");
	struct hash_data dst_buffer;
	int count;
	doca_error_t res;

	DOCA_LOG_INFO("dma_remote_copy_init()");

	dma_remote_copy_init(&pcie_addr, &send_state);

	while(true) 
	{
		res = dma_recv(&dst_buffer);
		if (res == DOCA_SUCCESS) {
			count = write(mapped_fd, (char*)&dst_buffer, sizeof(struct hash_data));
			if (count <= 0) 
				DOCA_LOG_ERR("write failed");
		} else {
			DOCA_LOG_ERR("dma_recv_error = %s", doca_get_error_string(res));
			break;
		}
	}

	return NULL;
}

void* doca_send(void *arg)
{
	DOCA_LOG_INFO("doca recv start");
	struct transfer_data_to_user data;
	int count;
	doca_error_t res;

	DOCA_LOG_INFO("dma_remote_sender_init()");
	dma_remote_sender_init(&pcie_addr, &recv_state);

	while(true)
	{
		count = read(mapped_fd, (char *)&data, sizeof(struct transfer_data_to_user));
		if(count <= 0) {
			if(count == 0) {
				DOCA_LOG_ERR("Data are not ready");
				continue;
			}
			DOCA_LOG_ERR("error in read");
			break;
		}

		if(data.buf == NULL) {
			gint64 *key = g_new(gint64, data.addr);
			gpointer gp = g_hash_table_lookup(hash, key);
			res = dma_send((struct hash_data *)gp);
			if(gp == NULL) continue; // already send
			if (res != DOCA_SUCCESS)
			{
				DOCA_LOG_ERR("dma send failed = %s", doca_get_error_string(res));
				break;
			}
		}
		else {
			hash_table_insert(data);
			if (hash_table_size >= TRANSFER_SIZE) {
				g_hash_table_foreach(hash, (GHFunc)h_dma_send, NULL);
				DOCA_LOG_INFO("total success = %d", h_dma_send_state);
				h_dma_send_state = 0;
				hash_table_size = 0;
				g_hash_table_destroy(hash);
				init_hash_table();
			}
			else {
				res = dma_metadata_send(data.addr);
				if (res != DOCA_SUCCESS) {
					DOCA_LOG_ERR("dma_metadata_send error = %s", doca_get_error_string(res));
					break;
				}
			}
		}
	}
	return NULL;
}
int main(int argc, char* argv[]) 
{
	if (argc < 4) 
	{
		printf("Usage : ./%s [receiver_ip] [receiver_port] ['server' or 'client']\n", argv[0]);
		return 0;
	}
	receiver_ip = argv[1];
	receiver_port = atoi(argv[2]);
	port = argv[2];

	printf("open %s\n", DEV_NAME);
	mapped_fd = open(DEV_NAME, O_RDWR, S_IRUSR | S_IWUSR);
	if (mapped_fd < 0) 
	{
		printf("open %s failed, errno = %d\n", DEV_NAME, errno);
		printf("strerror(errno) : %s\n", strerror(errno));
	}
	
	printf("init hash table\n");
	init_hash_table();

	printf("connect\n");
	if(!strcmp(argv[3], "client")) {
		sender_fd = send_socket(receiver_ip, receiver_port);
		if (sender_fd < 0) {
			DOCA_LOG_ERR("send_socket failed\n");
			return 0;
		}
	}
	else {
		sender_fd = receive_socket(port);
		if (sender_fd < 0) {
			DOCA_LOG_ERR("receive_socket failed");
			return 0;
		}
	}
	printf("send_thread start\n");
	pthread_create(&send_thread, NULL, doca_send, NULL);
	printf("recv_thread start\n");
	pthread_create(&recv_thread, NULL, doca_recv, NULL);
}
*/
int main(int argc, char* argv[]) 
{
	struct doca_argp_program_general_config *doca_general_config;
    struct doca_argp_program_type_config type_config = {
        .is_dpdk = false,
        .is_grpc = false
    };
	doca_argp_init("prefetch_user", &type_config, &prefetch_user_config);
	register_prefetch_user_params();
	doca_argp_start(argc, argv, &doca_general_config);

	struct hash_data data;
	struct hash_data cli_data;
	doca_error_t res;

	pcie_addr.bus = prefetch_user_config.bus_addr;
	pcie_addr.device = prefetch_user_config.device_addr;
	pcie_addr.function = prefetch_user_config.function_addr;

	if(prefetch_user_config.role == SERVER) {
		DOCA_LOG_INFO("port = %s", prefetch_user_config.port);
		sender_fd = receive_socket(prefetch_user_config.port);
		if (sender_fd < 0) {
			DOCA_LOG_ERR("Failed to accept");
			return 0;
		}
		if(prefetch_user_config.mode == SEND) {
			res = dma_remote_copy_init(&pcie_addr, &send_state, "my_mmap2", "my_inv2");
			res = dma_remote_copy_init(&pcie_addr, &recv_doorbell_state, "my_mmap3", "my_inv3");
		}
		else {
			res = dma_remote_copy_init(&pcie_addr, &recv_state, "my_mmap1", "my_inv1");
			res = dma_remote_copy_init(&pcie_addr, &send_doorbell_state, "my_mmap4", "my_inv4");
		}
	}
	else {
		sender_fd = send_socket(prefetch_user_config.receiver_ip, prefetch_user_config.receiver_port);
		if (sender_fd < 0) {
			DOCA_LOG_ERR("Failed to connect");
			return 0;
		}
		if(prefetch_user_config.mode == SEND) {
			res = dma_remote_sender_init(&pcie_addr, &send_state, "my_mmap1");
			res = dma_remote_sender_init(&pcie_addr, &send_doorbell_state, "my_mmap4");
		}
		else {
			res = dma_remote_sender_init(&pcie_addr, &recv_state, "my_mmap2");
			res = dma_remote_sender_init(&pcie_addr, &recv_doorbell_state, "my_mmap3");
		}
	}
	if (res != DOCA_SUCCESS) {
		DOCA_LOG_ERR("init error = %s", doca_get_error_string(res));
		return 0;
	}

	DOCA_LOG_INFO("send | recv start");
	if(prefetch_user_config.role == SERVER) {
		if(prefetch_user_config.mode == SEND) {
			res = dma_remote_copy_receiver(send_state, &data, sizeof(struct hash_data), sender_fd, &d_state, "my_mmap1");
			if(!printLog(res)) {close(sender_fd); return 0;}
			res = dma_remote_copy_receiver(recv_doorbell_state, &recv_doorbell, sizeof(recv_doorbell), sender_fd, &d_recv_doorbell_state, "my_mmap4");
			if(!printLog(res)) {close(sender_fd); return 0;}
			make_server_thread(&send_state, &d_state, &data, sizeof(struct hash_data), SEND);
		}
		else {
			// HOST->SMARTNIC DMA MEMORY
			res = dma_remote_copy_receiver(recv_state, &cli_data, sizeof(struct hash_data), sender_fd, &d_cli_state, "my_mmap2");
			if(!printLog(res)) {close(sender_fd); return 0;}
			// HOST->SMARTNIC DMA DOORBELL
			res = dma_remote_copy_receiver(send_doorbell_state, &send_doorbell, sizeof(send_doorbell), sender_fd, &d_send_doorbell_state, "my_mmap4");
			if(!printLog(res)) {close(sender_fd); return 0;}
		
			make_server_thread(&recv_state, &d_cli_state, &cli_data, sizeof(struct hash_data), RECV);
		}
	}
	else {
		if(prefetch_user_config.mode == SEND) {
			// HOST->SMARTNIC DMA MEMORY
			res = dma_remote_copy_sender(send_state, &data, sizeof(struct hash_data), sender_fd);
			if(!printLog(res)) {close(sender_fd); return 0;}
			// SMARTNIC->HOST DMA DOORBELL
			res = dma_remote_copy_sender(send_doorbell_state, &send_doorbell, sizeof(send_doorbell), sender_fd);
			if(!printLog(res)) {close(sender_fd); return 0;}
			make_client_thread(&send_state, &data, sizeof(struct hash_data), SEND);
		}
		else {
			// SMARTNIC->HOST DMA MEMORY
			res = dma_remote_copy_sender(recv_state, &cli_data, sizeof(struct hash_data), sender_fd);
			if(!printLog(res)) {close(sender_fd); return 0;}
			// HOST->SMARTNIC DMA DOORBEL
			res = dma_remote_copy_sender(recv_doorbell_state, &recv_doorbell, sizeof(recv_doorbell), sender_fd);
			if(!printLog(res)) {close(sender_fd); return 0;}
			make_client_thread(&recv_state, &cli_data, sizeof(struct hash_data), RECV);
		}
	}

	if(prefetch_user_config.mode == RECV)
		while(recv_thread_state) {}
	if(prefetch_user_config.mode == SEND)
		while(send_thread_state) {}

	if(prefetch_user_config.role == SERVER) {
		if(prefetch_user_config.mode == SEND) {
			dma_clear(send_state, d_state);
			// Point of HOST
			dma_clear(recv_doorbell_state, d_recv_doorbell_state);
		}
		else {
			dma_clear(recv_state, d_cli_state);
			// Point of HOST
			dma_clear(send_doorbell_state, d_send_doorbell_state);
		}
	}
	else {
		if(prefetch_user_config.mode == SEND) {
			dma_clear(send_state, d_state);
			dma_clear(send_doorbell_state, d_send_doorbell_state);
		}
		else {
			dma_clear(recv_state, d_cli_state);
			dma_clear(recv_doorbell_state, d_recv_doorbell_state);
		}
	}
	close(sender_fd);
	return 0;
}




