#ifndef _DOCA_DMA_H
#define _DOCA_DMA_H

#include "../../common/src/dma_common.h"
#include <doca_error.h>
#include <doca_argp.h>
#include <doca_log.h>
#include <doca_mmap.h>
#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_dma.h>

#define PAGE_SIZE 4096
#define DATA_SIZE 4104
#define unused(x) (void)(x)

struct prefetch_user_config {
	char *receiver_ip;
	uint16_t receiver_port;
	char *port;
	int role;
	int mode;
	uint8_t bus_addr;
	uint8_t device_addr;
	uint8_t function_addr;
};

struct thread_data {
	int mapped_fd;
	struct app_state *state;
	struct hash_data *buffer;
	size_t data_to_copy_len;
	struct doca_state *d_state;
};

struct doca_state {
	struct doca_buf *src_doca_buf;
	struct doca_buf *dst_doca_buf;
	struct doca_mmap *remote_mmap;
};

struct hash_data {
	uint64_t addr;
	uint64_t ts;
	char buf[PAGE_SIZE];
};

void register_prefetch_user_params(void);

int send_socket(char *ip, uint64_t port);
doca_error_t dma_remote_sender_init(struct doca_pci_bdf *pcie_addr, struct app_state *state, char *mmap_name);
doca_error_t dma_remote_copy_sender(struct app_state state, void *src_buffer, size_t length, int sender_fd);

int receive_socket(const char *port);
doca_error_t dma_remote_copy_init(struct doca_pci_bdf *pcie_addr, struct app_state *state, char *mmap_name, char *inv_name);
doca_error_t dma_remote_copy_receiver(struct app_state state, void *dst_buffer, size_t data_to_copy_len, int sender_fd, struct doca_state *d_state, char *mmap_name);
void* server_recv(void *arg);
void* server_send(void *arg);
void dma_clear(struct app_state state, struct doca_state d_state);

void* client_send(void *arg);
void* client_recv(void *arg);
void* server_send(void *arg);
void *server_recv(void *arg);
#endif
