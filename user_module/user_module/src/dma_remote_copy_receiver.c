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

#include <json-c/json.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

#include "prefetch_dma.h"
#include "prefetch_mmap.h"

DOCA_LOG_REGISTER(DMA_REMOTE_COPY_RECEIVER);

extern bool recv_thread_state;
extern bool send_thread_state;
extern uint8_t recv_doorbell;
extern uint8_t send_doorbell;
extern struct doca_state d_send_doorbell_state;
extern struct doca_state d_recv_doorbell_state;
extern struct app_state send_doorbell_state;
extern struct app_state recv_doorbell_state;
typedef enum MODE {
	SEND,
	RECV
}MODE;

struct timespec start, end;

bool wait_doorbell(MODE method);
bool set_doorbell(MODE method);

int 
receive_socket(const char *port)
{
	struct addrinfo *res, *it;
	struct addrinfo hints = {
		.ai_flags = AI_PASSIVE,
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM
	};
	int receiver_fd = -1, sender_fd = -1;
	int optval = 1;
	int queue_size = 1;

	if (getaddrinfo(NULL, port, &hints, &res)) {
		DOCA_LOG_ERR("Failed to retrieve network information");
		return -1;
	}

	for (it = res ; it ; it = it->ai_next) {
		receiver_fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
		if (receiver_fd >= 0) {
			setsockopt(receiver_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
			if (!bind(receiver_fd, it->ai_addr, it->ai_addrlen))
				break;
			close(receiver_fd);
			receiver_fd = -1;
		}
	}

	freeaddrinfo(res);

	if (receiver_fd < 0) {
		DOCA_LOG_ERR("Port listening failed");
		return -1;
	}

	listen(receiver_fd, queue_size);
	
	DOCA_LOG_INFO("Waiting for sender node to send exported data");

	sender_fd = accept(receiver_fd, NULL, 0);

	close(receiver_fd);
	return sender_fd;
}

static bool
receive_json_from_sender(char *export_buffer, size_t export_buffer_len, char **remote_addr,
			size_t *remote_addr_len, int sender_fd)
{
	struct json_object *from_export_json;
	struct json_object *addr;
	struct json_object *len;
	int bytes_ret;

	bytes_ret = recv(sender_fd, export_buffer, export_buffer_len, 0);

	if (bytes_ret == -1) {
		DOCA_LOG_ERR("Couldn't receive data from sender node");
		return false;
	} else if (bytes_ret == export_buffer_len) {
		if (export_buffer[export_buffer_len - 1] != '\0') {
			DOCA_LOG_ERR("Exported data buffer size is not sufficient");
			return false;
		}
	}

	DOCA_LOG_INFO("Exported data was received");
	
	/* Parse the export json */
	from_export_json = json_tokener_parse(export_buffer);
	json_object_object_get_ex(from_export_json, "addr", &addr);
	json_object_object_get_ex(from_export_json, "len", &len);
	*remote_addr = (char *)json_object_get_int64(addr);
	*remote_addr_len = (size_t)json_object_get_int64(len);
	json_object_put(from_export_json);
	DOCA_LOG_INFO("received addr = %p, len = %ld", *remote_addr, *remote_addr_len);

	return true;
}

static void
send_ack_to_sender(int sender_fd)
{
	int ret;
	char ack_buffer[] = "DMA operation on receiver node was completed";
	int length = strlen(ack_buffer) + 1;

	ret = write(sender_fd, ack_buffer, length);
	if (ret != length)
		DOCA_LOG_ERR("Failed to send ack message to sender node");
}

doca_error_t
dma_remote_copy_init(struct doca_pci_bdf *pcie_addr, struct app_state *state, char *mmap_name, char *inv_name)
{
	doca_error_t res;
	uint32_t max_chunks = 1;

	res = open_local_device(pcie_addr, state);
	if (res != DOCA_SUCCESS)
		return res;

	res = create_core_objects(state, mmap_name, inv_name);
	if (res != DOCA_SUCCESS) {
		destroy_core_objects(state);
		return res;
	}

	res = init_core_objects(state, max_chunks);
	if (res != DOCA_SUCCESS) {
		cleanup_core_objects(state);
		destroy_core_objects(state);
		return res;
	}

    return res;
}

doca_error_t
dma_remote_copy_receiver(struct app_state state, void *dst_buffer, size_t data_to_copy_len, int sender_fd, struct doca_state *d_state, char *mmap_name)
{
	/* Receive exported data from sender */
	doca_error_t res;
	uint32_t pg_sz = 1024 * 4 * 2;
	struct hash_data *export_json;
	char export_buffer[DATA_SIZE] = {0};
	char *remote_addr;
	size_t remote_addr_len;

    export_json = (struct hash_data *)malloc(sizeof(struct hash_data));
    if(!export_json) {
        DOCA_LOG_ERR("malloc failed");
		return -1;
    }

	DOCA_LOG_INFO("populate_mmap");
	res = populate_mmap(state.mmap, (char *)dst_buffer, data_to_copy_len, pg_sz);
	if (res != DOCA_SUCCESS) {
		cleanup_core_objects(&state);
		destroy_core_objects(&state);
		return res;
    }

	DOCA_LOG_INFO("receive_json_from_sender");
	if (!receive_json_from_sender(export_buffer, sizeof(export_buffer) / sizeof(char), &remote_addr,
				      &remote_addr_len, sender_fd)) {
		cleanup_core_objects(&state);
		destroy_core_objects(&state);
		return DOCA_ERROR_NOT_CONNECTED;
	}

	/* Create a local DOCA mmap from exported data */
	DOCA_LOG_INFO("doca_mmap_create_from_export");
	DOCA_LOG_INFO("remote addr = %p, remote addr len = %ld", remote_addr, remote_addr_len);
	res = doca_mmap_create_from_export(mmap_name, (uint8_t *)export_buffer, sizeof(export_buffer) + 1, state.dev,
					   &d_state->remote_mmap);
	if (res != DOCA_SUCCESS) {
		DOCA_LOG_ERR("doca_mmap_create_from_export failed");
		cleanup_core_objects(&state);
		destroy_core_objects(&state);
		return res;
	}
	
	/* Construct DOCA buffer for each address range */
	DOCA_LOG_INFO("doca_buf_inventory_buf_by_addr");
	res = doca_buf_inventory_buf_by_addr(state.buf_inv, d_state->remote_mmap, remote_addr, remote_addr_len, &d_state->src_doca_buf);
	if (res != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to acquire DOCA buffer representing remote buffer: %s", doca_get_error_string(res));
		doca_mmap_destroy(d_state->remote_mmap);
		cleanup_core_objects(&state);
		destroy_core_objects(&state);
		return res;
	}

	/* Construct DOCA buffer for each address range */
	DOCA_LOG_INFO("doca_buf_inventory_buf_by_addr");
	res = doca_buf_inventory_buf_by_addr(state.buf_inv, state.mmap, (char *)dst_buffer, data_to_copy_len, &d_state->dst_doca_buf);
	if (res != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to acquire DOCA buffer representing destination buffer: %s", doca_get_error_string(res));
		doca_buf_refcount_rm(d_state->src_doca_buf, NULL);
		doca_mmap_destroy(d_state->remote_mmap);
		cleanup_core_objects(&state);
		destroy_core_objects(&state);
		return res;
	}

	DOCA_LOG_INFO("Send ACK to Sender");
	send_ack_to_sender(sender_fd);
	return DOCA_SUCCESS;
}
// HOST->SMARTNIC
// send doorbell로 판단
void *
server_recv(void *arg)
{
	struct doca_event event = {0};
	struct doca_job doca_job = {0};
	struct doca_dma_job_memcpy dma_job = {0};
	struct thread_data *tdata = (struct thread_data *)arg;
	int mapped_fd = tdata->mapped_fd;
	struct app_state *state = tdata->state;
	struct hash_data *dst_buffer = tdata->buffer;
	size_t data_to_copy_len = tdata->data_to_copy_len;
	struct doca_state *d_state = tdata->d_state;
	doca_error_t res;

	// client_send -> server_recv
	// doorbell은 HOST의 입장
	while(true) {
		wait_doorbell(SEND);
		if(!recv_thread_state) break;
		if(!send_doorbell) continue;
		/* Construct DMA job */
		doca_job.type = DOCA_DMA_JOB_MEMCPY;
		doca_job.flags = DOCA_JOB_FLAGS_NONE;
		doca_job.ctx = state->ctx;
	
		dma_job.base = doca_job;
		dma_job.dst_buff = d_state->dst_doca_buf;
		dma_job.src_buff = d_state->src_doca_buf;
		dma_job.num_bytes_to_copy = data_to_copy_len;

		/* Enqueue DMA job */
		clock_gettime(CLOCK_BOOTTIME, &start);
		res = doca_workq_submit(state->workq, &dma_job.base);
		if (res != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to submit DMA job: %s", doca_get_error_string(res));
			recv_thread_state = false;
			break;
		}

		/* Wait for job completion */
		while ((res = doca_workq_progress_retrieve(state->workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE)) ==
			   DOCA_ERROR_AGAIN) {
			/* Do nothing */
		}

		if (res != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to submit DMA job: %s", doca_get_error_string(res));
            recv_thread_state = false;
			break;
		}

		/* On DOCA_SUCCESS, Verify DMA job result */
		if (event.result.u64 == DOCA_SUCCESS) {
			// if not ready, force to overlap data
			if(mapped_file_write(mapped_fd, dst_buffer, data_to_copy_len) < 0) break;
			set_doorbell(SEND);
		} else {
			DOCA_LOG_ERR("DMA job returned unsuccessfully");
			res = DOCA_ERROR_UNKNOWN;
			recv_thread_state = false;
			break;
		}
	}
	return NULL;
}
// SMARTNIC->HOST
// recv doorbell 로 판단
void *
server_send(void *arg)
{
    struct doca_event event = {0};
    struct doca_job doca_job = {0};
    struct doca_dma_job_memcpy dma_job = {0};
    struct thread_data *tdata = (struct thread_data *)arg;
	int mapped_fd = tdata->mapped_fd;
    struct app_state *state = tdata->state;
    struct hash_data *dst_buffer = tdata->buffer;
    size_t data_to_copy_len = tdata->data_to_copy_len;
    struct doca_state *d_state = tdata->d_state;
    doca_error_t res;

	// server_send -> client_recv (recv_doorbell)
	// doorbell은 HOST의 입장
    while(send_thread_state) {
		wait_doorbell(RECV);
		if(!send_thread_state) break;
		if(!recv_doorbell) continue;
		/* need to code read */
		if(mapped_file_read(mapped_fd, dst_buffer, data_to_copy_len) < 0) break;
		if(!send_thread_state) break;
        /* Construct DMA job */
        doca_job.type = DOCA_DMA_JOB_MEMCPY;
        doca_job.flags = DOCA_JOB_FLAGS_NONE;
        doca_job.ctx = state->ctx;

        dma_job.base = doca_job;
		// change DMA Position
        dma_job.dst_buff = d_state->src_doca_buf;
        dma_job.src_buff = d_state->dst_doca_buf;
        dma_job.num_bytes_to_copy = data_to_copy_len;

        /* Enqueue DMA job */
		clock_gettime(CLOCK_BOOTTIME, &start);
        res = doca_workq_submit(state->workq, &dma_job.base);
        if (res != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to submit DMA job: %s", doca_get_error_string(res));
            send_thread_state = false;
			break;
		}

        /* Wait for job completion */
        while ((res = doca_workq_progress_retrieve(state->workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE)) ==
               DOCA_ERROR_AGAIN) {
            /* Do nothing */
        }

        if (res != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to submit DMA job: %s", doca_get_error_string(res));
            send_thread_state = false;
			break;
        }

        /* On DOCA_SUCCESS, Verify DMA job result */
        if (event.result.u64 == DOCA_SUCCESS) {
			// if not ready, force to overlap data
			set_doorbell(RECV);
        } else {
            DOCA_LOG_ERR("DMA job returned unsuccessfully");
            res = DOCA_ERROR_UNKNOWN;
            send_thread_state = false;
			break;
        }
    }
    return NULL;
}

bool 
wait_doorbell(MODE method)
{
	struct doca_event event = {0};
    struct doca_job doca_job = {0};
    struct doca_dma_job_memcpy dma_job = {0};
	struct app_state *state = (method == SEND ? &send_doorbell_state : &recv_doorbell_state);
	int loop_count = 0, loop_threshold = 10000000;
	doca_error_t res;

	// want_state == 0 : client_send, server_recv => send_doorbell
	// want_state == 1 : client_recv, server_send => recv_doorbell
	while(loop_count++ < loop_threshold) {
		if(method == SEND && send_doorbell) {
			clock_gettime(CLOCK_BOOTTIME, &end);
			double accum = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / (double)1000000000L;
			DOCA_LOG_INFO("latency = %lf", accum);
			break;
		}
		if(method == RECV && recv_doorbell) {
			clock_gettime(CLOCK_BOOTTIME, &end);
			double accum = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / (double)1000000000L;
			DOCA_LOG_INFO("latency = %lf", accum);
			break;
		}
		/* Construct DMA job */
        doca_job.type = DOCA_DMA_JOB_MEMCPY;
        doca_job.flags = DOCA_JOB_FLAGS_NONE;
        doca_job.ctx = state->ctx;

        dma_job.base = doca_job;
        // change DMA Position
		if(method == SEND) {
			// HOST -> SMARTNIC
			dma_job.dst_buff = d_send_doorbell_state.dst_doca_buf;
			dma_job.src_buff = d_send_doorbell_state.src_doca_buf;
		}
		else {
			// SMARTNIC -> HOST
			dma_job.dst_buff = d_recv_doorbell_state.dst_doca_buf;
			dma_job.src_buff = d_recv_doorbell_state.src_doca_buf;
		}
        dma_job.num_bytes_to_copy = 1;

        res = doca_workq_submit(state->workq, &dma_job.base);
        if (res != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to submit DMA job: %s", doca_get_error_string(res));
            if(method == SEND) send_thread_state = false;
			else recv_thread_state = false;
            return false;
        }

        /* Wait for job completion */
        while ((res = doca_workq_progress_retrieve(state->workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE)) ==
               DOCA_ERROR_AGAIN) {
            /* Do nothing */
        }

        if (res != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to submit DMA job: %s", doca_get_error_string(res));
            if(method == SEND) send_thread_state = false;
			else recv_thread_state = false;
            return false;
        }

        /* On DOCA_SUCCESS, Verify DMA job result */
        if (event.result.u64 == DOCA_SUCCESS) {
        } else {
            DOCA_LOG_ERR("DMA job returned unsuccessfully");
            res = DOCA_ERROR_UNKNOWN;
            if(method == SEND) send_thread_state = false;
			else recv_thread_state = false;
            return false;
        }
    }
	return true;
}

bool
set_doorbell(MODE method)
{
    struct doca_event event = {0};
    struct doca_job doca_job = {0};
    struct doca_dma_job_memcpy dma_job = {0};
    struct app_state *state = (method == SEND ? &send_doorbell_state : &recv_doorbell_state);
    doca_error_t res;

	if(method == SEND) send_doorbell = 0;
	else recv_doorbell = 0;
    // want_state == 0 : client_send, server_recv
    // want_state == 1 : client_recv, server_send
    /* Construct DMA job */
    doca_job.type = DOCA_DMA_JOB_MEMCPY;
    doca_job.flags = DOCA_JOB_FLAGS_NONE;
    doca_job.ctx = state->ctx;

    dma_job.base = doca_job;
    // change DMA Position
    if(method == SEND) {
		// HOST -> SMARTNIC
		dma_job.dst_buff = d_send_doorbell_state.src_doca_buf;
		dma_job.src_buff = d_send_doorbell_state.dst_doca_buf;
	}
	else {
		// SMARTNIC -> HOST
		dma_job.dst_buff = d_recv_doorbell_state.src_doca_buf;
		dma_job.src_buff = d_recv_doorbell_state.dst_doca_buf;
	}
	dma_job.num_bytes_to_copy = 1;

	res = doca_workq_submit(state->workq, &dma_job.base);
	if (res != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to submit DMA job: %s", doca_get_error_string(res));
		if(method == SEND) send_thread_state = false;
		else recv_thread_state = false;
		return false;
	}

	/* Wait for job completion */
	while ((res = doca_workq_progress_retrieve(state->workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE)) ==
		   DOCA_ERROR_AGAIN) {
		/* Do nothing */
	}

	if (res != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to submit DMA job: %s", doca_get_error_string(res));
		if(method == SEND) send_thread_state = false;
		else recv_thread_state = false;
		return false;
	}

	/* On DOCA_SUCCESS, Verify DMA job result */
	if (event.result.u64 == DOCA_SUCCESS) {
		return true;
	} else {
		DOCA_LOG_ERR("DMA job returned unsuccessfully");
		res = DOCA_ERROR_UNKNOWN;
		if(method == SEND) send_thread_state = false;
		else recv_thread_state = false;
		return false;
	}
}

void
dma_clear(struct app_state state, struct doca_state d_state)
{
	DOCA_LOG_INFO("doca_buf_refcount_rm");
	if (doca_buf_refcount_rm(d_state.src_doca_buf, NULL) | doca_buf_refcount_rm(d_state.dst_doca_buf, NULL))
		DOCA_LOG_ERR("Failed to decrease DOCA buffer reference count");

	/* Destroy remote memory map */
	DOCA_LOG_INFO("doca_mmap_destroy");
	if (doca_mmap_destroy(d_state.remote_mmap))
		DOCA_LOG_ERR("Failed to destroy remote memory map");
	
	cleanup_core_objects(&state);
	destroy_core_objects(&state);
}
