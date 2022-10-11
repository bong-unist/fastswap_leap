#ifndef _PREFETCH_MMAP_H
#define _PREFETCH_MMAP_H

#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/ptrace.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <uapi/linux/fs.h>
#include <linux/types.h>
#include <linux/hashtable.h>

#define DEV_NAME "mmap"
#define DATA_SIZE (1 * (1 << PAGE_SHIFT))
#define PAGE_CNT 64
#define vm_fault_t unsigned int

struct buf_info {
	atomic_t head;
	atomic_t tail;
	atomic_t head_round;
	atomic_t tail_round;
	int size;
};

struct rdma_buf {
	uint64_t ts;
	uint64_t host_page;
	struct page *page;
};

struct transfer_data_to_user {
	uint64_t addr;
	char *buf;
};

struct prefetch_data {
	uint64_t addr; // key
	uint64_t ts; // time
	char *buf; // value
	struct hlist_node my_hash_list; // hash_list 
};

struct write_prefetch_data {
	uint64_t addr;
	u64 offset;
	uint64_t ts;
};

extern struct vm_operations_struct vma_ops;
extern struct file_operations mmap_fops;

void before_write(struct page *page, uint64_t ts);
void prefetch_lru_drain_wrapper(uint64_t addr, uint8_t type);
/*
DEFINE_HASHTABLE(h_prefetch_data, 6);
DEFINE_HASHTABLE(h_metadata_prefetch_data, 6);

atomic_t send_metadata;

struct rdma_buf rdma_buf[PAGE_CNT];
struct buf_info buf_info;

const unsigned int MINOR_BASE = 0;
const unsigned int MINOR_NUM = 1;
unsigned int mmapdev_major;
struct cdev *mmapdev_cdev = NULL;
struct class *mmapdev_class = NULL;

int *data = NULL;
atomic_t counter = ATOMIC_INIT(0);
*/
#endif
