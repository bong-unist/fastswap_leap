#ifndef _PREFETCH_MMAP_H
#define _PREFETCH_MMAP_H

#include "prefetch_dma.h"

int mapped_file_read(int mapped_fd, struct hash_data *buffer, size_t data_to_copy_len);
int mapped_file_write(int mapped_fd, struct hash_data *buffer, size_t data_to_copy_len);

#endif
