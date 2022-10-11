#include <stdio.h>
#include <fcntl.h>
#include "prefetch_mmap.h"

DOCA_LOG_REGISTER("prefetch_mmap");

extern struct prefetch_user_config prefetch_user_config;
extern bool send_thread_state;
extern bool recv_thread_state;

typedef enum ROLE {
	SERVER,
	CLIENT
} ROLE;

typedef enum MODE {
	SEND,
	RECV
} MODE;

int mapped_file_read(int mapped_fd, struct hash_data *buffer, size_t data_to_copy_len) 
{
	int size;
	while(true) {
		size = read(mapped_fd, buffer, data_to_copy_len);
		if(size == 0) continue;
		if(size < 0) {
			DOCA_LOG_ERR("mapped file read failed");
			break;
		}
		return size;
	}
	if(prefetch_user_config.mode == SEND) send_thread_state = false;
	if(prefetch_user_config.mode == RECV) recv_thread_state = false;
	return -1;
}

int mapped_file_write(int mapped_fd, struct hash_data *buffer, size_t data_to_copy_len)
{
	int size;
	while(true) {
		size = write(mapped_fd, buffer, data_to_copy_len);
		if(size == 0) continue;
		if(size < 0) {
			DOCA_LOG_ERR("mapped file write failed");
			break;
		}
		return size;
	}
	if(prefetch_user_config.mode == SEND) send_thread_state = false;
	if(prefetch_user_config.mode == RECV) recv_thread_state = false;
	return -1;
}
