/*
 * Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>

#include "prefetch_dma.h"
#include "prefetch_mmap.h"

extern bool recv_thread_state;
extern bool send_thread_state;
extern uint8_t recv_doorbell;
extern uint8_t send_doorbell;

DOCA_LOG_REGISTER(DMA_REMOTE_COPY_SENDER);

int
send_socket(char *ip, uint64_t port)
{
	struct sockaddr_in addr;
	struct timeval timeout = {
		.tv_sec = 5,
	};
	int sender_fd;

	sender_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (sender_fd < 0) {
		DOCA_LOG_ERR("socket() failed");
		return -1;
	}

	DOCA_LOG_INFO("setsockopt()");
	setsockopt(sender_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

	addr.sin_addr.s_addr = inet_addr(ip);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	DOCA_LOG_INFO("connect()");
	if (connect(sender_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		DOCA_LOG_ERR("Couldn't establish a connection to receiver node");
		close(sender_fd);
		return -1;
	}

	return sender_fd;
}

bool
send_json_to_receiver(int sender_fd, char *export_str, size_t export_str_len)
{
	int ret;
	char ack_buffer[1024] = {0};
	char exp_ack[] = "DMA operation on receiver node was completed";

	DOCA_LOG_INFO("write()");
	DOCA_LOG_INFO("data = %s\n", export_str);
	ret = write(sender_fd, export_str, export_str_len);
	if (ret != (int)export_str_len) {
		DOCA_LOG_ERR("Failed to send data to receiver node");
		close(sender_fd);
		return false;
	}

	DOCA_LOG_INFO("Waiting for receiver node to acknowledge DMA operation was ended");
    if (recv(sender_fd, ack_buffer, sizeof(ack_buffer), 0) < 0) {
        DOCA_LOG_ERR("Failed to receive ack message");
        close(sender_fd);
        return false;
    }

    if (strcmp(exp_ack, ack_buffer)) {
        DOCA_LOG_ERR("Ack message is not correct");
        close(sender_fd);
        return false;
    }

    DOCA_LOG_INFO("Ack message was received, closing memory mapping");

	return true;
}

doca_error_t
dma_remote_sender_init(struct doca_pci_bdf *pcie_addr, struct app_state *state, char *mmap_name)
{
	//struct app_state state = {0};
	doca_error_t res;

	res = open_local_device(pcie_addr, state);
	if (res != DOCA_SUCCESS)
		return res;

	res = init_core_objects_sender(state, mmap_name);
	if (res != DOCA_SUCCESS) {
		destroy_core_objects_sender(state);
		return res;
	}

    return res;
}

doca_error_t
dma_remote_copy_sender(struct app_state state, void *src_buffer, size_t length, int sender_fd)
{
    doca_error_t res;
    char *export_str;
    size_t export_str_len;
	size_t pg_sz = 1024 * 4 * 2;

	DOCA_LOG_INFO("populate_mmap\n");
	res = populate_mmap(state.mmap, (char *)src_buffer, length, pg_sz);
	if (res != DOCA_SUCCESS) {
		destroy_core_objects_sender(&state);
		return res;
	}
    	
	DOCA_LOG_INFO("doca_mmap_export\n");
    res = doca_mmap_export(state.mmap, state.dev, (uint8_t **)&export_str, &export_str_len);
	if (res != DOCA_SUCCESS) {
		destroy_core_objects_sender(&state);
		return res;
	}

	/* Send exported string and wait for ack that DMA was done on receiver node */
	if (!send_json_to_receiver(sender_fd, export_str, export_str_len)) {
		destroy_core_objects_sender(&state);
		free(export_str);
		return DOCA_ERROR_NOT_CONNECTED;
	}

    return res;
}

void *
client_recv(void *arg)
{
	struct thread_data *tdata = (struct thread_data *)arg;
	int mapped_fd = tdata->mapped_fd;
	struct app_state *state = tdata->state;
	struct hash_data *buffer = tdata->buffer;
	size_t data_to_copy_len = tdata->data_to_copy_len;
	unused(state);

	/* mmap_write 함수 필요 */
	while(true) {
		if(mapped_file_write(mapped_fd, buffer, data_to_copy_len) < 0) break;
		recv_doorbell = 1;
		while(recv_doorbell){}
	}
	return NULL;
}

void *
client_send(void *arg)
{
	struct thread_data *tdata = (struct thread_data *)arg;
	int mapped_fd = tdata->mapped_fd;
	struct app_state *state = tdata->state;
    struct hash_data *buffer = tdata->buffer;
    size_t data_to_copy_len = tdata->data_to_copy_len;
	unused(state);

	/* mmap_read 함수 필요 */
	while(true) {
		if(mapped_file_read(mapped_fd, buffer, data_to_copy_len) < 0) break;
		send_doorbell = 1;
		while(send_doorbell) {}
	}
	return NULL;
}
