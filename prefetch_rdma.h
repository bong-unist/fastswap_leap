#ifndef _SSWAP_RDMA_H
#define _SSWAP_RDMA_H

#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>
#include <linux/inet.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/mm_types.h>
#include <linux/gfp.h>
#include <linux/pagemap.h>
#include <linux/spinlock.h>

enum qp_type {
	QP_READ_SYNC,
	QP_READ_ASYNC,
	QP_WRITE_SYNC
};

struct sswap_rdma_dev {
	struct ib_device *dev;
	struct ib_pd *pd;
};

struct rdma_req {
	struct completion done;
	struct list_head list;
	struct ib_cqe cqe;
	u64 dma;
	struct page *page;
	size_t size;
	bool is_page;
	int request_id;
};

struct sswap_rdma_ctrl;

struct rdma_queue {
	struct ib_qp *qp;
	struct ib_cq *cq;
	spinlock_t cq_lock;
	enum qp_type qp_type;

	struct sswap_rdma_ctrl *ctrl;

	struct rdma_cm_id *cm_id;
	int cm_error;
	/*
	   커널의 semaphore는 여러 CPU에서 병렬적으로 접근이 가능하도록 만들어 졌기 때문에 
	   지역 변수로 semaphore를 설정하게 되면, 문제가 발생할 수 있다
	   따라서 struct completion이 kerenl 2.4.7에서 등장하게 된다
	   completion은 한 task가 다른 task에게 작업이 완료되었음을 통지하는 간단한 매커니즘으로 되어있다
	   completion 내부는 spinlock를 사용하여 동시에 호출될 수 없도록 작성되어 있다
	*/
	struct completion cm_done;
	
	atomic_t pending;
};

struct sswap_rdma_memregion {
	u64 baseaddr;
	u32 key;
};

struct sswap_rdma_ctrl {
	struct sswap_rdma_dev *rdev;
	struct rdma_queue *queues;
	struct sswap_rdma_memregion servermr;
	
	union{
		struct sockaddr addr;
		struct sockaddr_in addr_in;
	};

	union{
		struct sockaddr srcaddr;
		struct sockaddr_in srcaddr_in;
	};
};

struct rdma_queue *sswap_rdma_get_queue(unsigned int idx, enum qp_type qp_type);
enum qp_type get_queue_type(unsigned int idx);
int sswap_rdma_read_async(uint64_t page_address, u64 roffset, uint64_t ts);
int sswap_rdma_read_sync(uint64_t page_address, u64 roffset, uint64_t ts);
int sswap_rdma_write(uint64_t page_address, u64 offset, uint64_t ts, char *buf);
int host_rdma_read_sync(struct page *page, u64 roffset);
void host_rdma_write(struct page *page, uint64_t ts);
int rdma_init(void);
void atomic_head_inc(void);
void atomic_tail_inc(void);
void atomic_head_inc_write(void);
void atomic_tail_inc_write(void);
void atomic_write_idx_inc(void);
#endif
