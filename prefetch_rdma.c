#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "prefetch_mmap.h"
#include "prefetch_rdma.h"
#include <linux/slab.h>
#include <linux/cpumask.h>
#define PAGE_CNT 64

/************************************/
DECLARE_HASHTABLE(h_prefetch_data, 6);
DECLARE_HASHTABLE(h_metadata_prefetch_data, 6);
// host -> use for temporary store
// smartnic -> use for rdma write
DECLARE_HASHTABLE(h_write_prefetch_data, 6);

EXPORT_SYMBOL(h_prefetch_data);
EXPORT_SYMBOL(h_metadata_prefetch_data);
EXPORT_SYMBOL(h_write_prefetch_data);

struct rdma_buf rdma_buf[PAGE_CNT];
struct buf_info buf_info;

struct rdma_buf write_rdma_buf[PAGE_CNT];
struct buf_info write_buf_info;

atomic_t write_idx;
uint64_t write_addr[PAGE_CNT];

static int request_id;

/**********************************/

static struct sswap_rdma_ctrl *gctrl;
static int numcpus;
static int numqueues;
static int serverport;
static struct kmem_cache *req_cache;
static char serverip[INET_ADDRSTRLEN];
static char clientip[INET_ADDRSTRLEN];

module_param_named(sport, serverport, int, 0644);
module_param_string(sip, serverip, INET_ADDRSTRLEN, 0644);
module_param_string(cip, clientip, INET_ADDRSTRLEN, 0644);

#define CONNECTION_TIMEOUT_MS 5000
#define QP_QUEUE_DEPTH 256
#define QP_MAX_RECV_WR 4
#define QP_MAX_SEND_WR (4096)
#define CQ_NUM_CQES (QP_MAX_SEND_WR)
#define POLL_BATCH_HIGH (QP_MAX_SEND_WR / 4)

static int sswap_rdma_addone(struct ib_device *dev)
{
    pr_info("sswap_rdma_addone() = %s\n", dev->name);
	return 0;
}

static void sswap_rdma_removeone(struct ib_device *ib_device, void *client_data)
{
	pr_info("sswap_rdma_removeone()\n");
}

static struct ib_client sswap_rdma_ib_client = {
    .name   = "sswap_rdma",
    .add    = sswap_rdma_addone,
    .remove = sswap_rdma_removeone
};

inline static int sswap_rdma_wait_for_cm(struct rdma_queue *queue)
{
  wait_for_completion_interruptible_timeout(&queue->cm_done,
    msecs_to_jiffies(CONNECTION_TIMEOUT_MS) + 1);
  return queue->cm_error;
}

static struct sswap_rdma_dev *sswap_rdma_get_device(struct rdma_queue *q)
{
	struct sswap_rdma_dev *rdev = NULL;

	pr_info("start: %s\n", __FUNCTION__);
	if(!q->ctrl->rdev) {
		/* 
		   kzalloc은 vmalloc과 달리 메모리를 0으로 초기화 하여 가져온다
		*/
		rdev = kzalloc(sizeof(*rdev), GFP_KERNEL);
		if(!rdev) {
			pr_err("no memory\n");
			goto out_err;
		}
		/* ib_device가 담겨서 온다 */
		rdev->dev = q->cm_id->device;
		
		pr_info("selecting device %s\n", rdev->dev->name);
		/* 해당 device에서 사용할 protection domain 설정 */
		rdev->pd = ib_alloc_pd(rdev->dev, 0);
		if(IS_ERR(rdev->pd)) {
			pr_err("ib_alloc_pd\n");
			goto out_free_dev;
		}

		if(!(rdev->dev->attrs.device_cap_flags & IB_DEVICE_MEM_MGT_EXTENSIONS)) {
			pr_err("memory registrations not supported\n");
			goto out_free_pd;
		}

		q->ctrl->rdev = rdev;
	}
	pr_info("end: %s\n", __FUNCTION__);
	return q->ctrl->rdev;

out_free_pd:
	ib_dealloc_pd(rdev->pd);
out_free_dev:
	kfree(rdev);
out_err:
	return NULL;
}

static void sswap_rdma_qp_event(struct ib_event *e, void *c)
{
	pr_info("sswap_rdma_qp_event\n");
}
/* 
	cq에 따라서 qp를 만든다
*/
static int sswap_rdma_create_qp(struct rdma_queue *queue)
{
	struct sswap_rdma_dev *rdev = queue->ctrl->rdev;
	struct ib_qp_init_attr init_attr;
	int ret;

	pr_info("start: %s\n", __FUNCTION__);

	memset(&init_attr, 0, sizeof(init_attr));
	init_attr.event_handler = sswap_rdma_qp_event;
	init_attr.cap.max_send_wr = QP_MAX_SEND_WR;
	init_attr.cap.max_recv_wr = QP_MAX_RECV_WR;
	init_attr.cap.max_recv_sge = 1;
	init_attr.cap.max_send_sge = 1;
	init_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
	init_attr.qp_type = IB_QPT_RC;
	init_attr.send_cq = queue->cq;
	init_attr.recv_cq = queue->cq;
	//init_attr.create_flags = IB_QP_EXP_CREATE_ATOMIC_BE_REPLY & 0;
	init_attr.create_flags = 0;

	ret = rdma_create_qp(queue->cm_id, rdev->pd, &init_attr);
	if(ret) {
		pr_err("rdma_create_qp failed: %d\n", ret);
		return ret;
	}
	queue->qp = queue->cm_id->qp;
	pr_info("end: %s\n", __FUNCTION__);
	return ret;
}

static int sswap_rdma_create_queue_ib(struct rdma_queue *q)
{
	struct ib_device *ibdev = q->ctrl->rdev->dev;
	int ret;
	int comp_vector = 0;

	pr_info("start: %s\n", __FUNCTION__);

	/* queue type에 따라 completion queue를 다르게 만든다 */
	if(q->qp_type == QP_READ_ASYNC) 
		q->cq = ib_alloc_cq(ibdev, q, CQ_NUM_CQES, comp_vector, IB_POLL_SOFTIRQ);
	else
		q->cq = ib_alloc_cq(ibdev, q, CQ_NUM_CQES, comp_vector, IB_POLL_DIRECT);

	if(IS_ERR(q->cq)) {
		ret = PTR_ERR(q->cq);
		goto out_err;
	}

	ret = sswap_rdma_create_qp(q);
	if(ret)
		goto out_destroy_ib_cq;
	pr_info("end: %s\n", __FUNCTION__);
	return 0;

out_destroy_ib_cq:
	ib_free_cq(q->cq);
out_err:
	pr_info("end: %s\n", __FUNCTION__);
	return ret;
}

static void sswap_rdma_destroy_queue_ib(struct rdma_queue *q)
{
	struct sswap_rdma_dev *rdev;
	struct ib_device *ibdev;

	pr_info("start: %s\n", __FUNCTION__);

	rdev = q->ctrl->rdev;
	ibdev = rdev->dev;

	ib_free_cq(q->cq);
}

static int sswap_rdma_addr_resolved(struct rdma_queue *q)
{
	struct sswap_rdma_dev *rdev = NULL;
	int ret;

	pr_info("start: %s\n", __FUNCTION__);

	rdev = sswap_rdma_get_device(q);
	if(!rdev) {
		pr_err("no device found\n");
		return -ENODEV;
	}

	ret = sswap_rdma_create_queue_ib(q);
	if(ret) 
		return ret;

	ret = rdma_resolve_route(q->cm_id, CONNECTION_TIMEOUT_MS);
	if(ret) {
		pr_err("rdma_resolve_route failed\n");
		sswap_rdma_destroy_queue_ib(q);
	}
	pr_info("end: %s\n", __FUNCTION__);
	return 0;
}

static int sswap_rdma_route_resolved(struct rdma_queue *q, struct rdma_conn_param *conn_params)
{
	struct rdma_conn_param param = {};
	int ret;
	pr_info("start: %s\n", __FUNCTION__);
	/* qp_num 는 queue pair의 번호를 의미한다 */
	param.qp_num = q->qp->qp_num;
	param.flow_control = 1;
	param.responder_resources = 16;
	param.initiator_depth = 16;
	param.retry_count = 7;
	param.rnr_retry_count = 7;
	param.private_data = NULL;
	param.private_data_len = 0;
	param.srq = 0; // ybim
	param.qkey = 0; // ybim

	pr_info("max_qp_rd_atom = %d max_qp_init_rd_atom = %d\n",
			q->ctrl->rdev->dev->attrs.max_qp_rd_atom,
			q->ctrl->rdev->dev->attrs.max_qp_init_rd_atom);

	ret = rdma_connect_locked(q->cm_id, &param); // ybim
	if(ret) {
		pr_err("rdma_connect failed (%d)\n", ret);
		sswap_rdma_destroy_queue_ib(q);
	}
	pr_info("end: %s\n", __FUNCTION__);
	return 0;
}

static int sswap_rdma_conn_established(struct rdma_queue *q)
{
	pr_info("connection established\n");
	return 0;
}

static int sswap_rdma_cm_handler(struct rdma_cm_id *cm_id, struct rdma_cm_event *ev)
{
	struct rdma_queue *queue = cm_id->context;
	int cm_error = 0;

	pr_info("cm_handler_msg: %s (%d) status %d id %p\n", rdma_event_msg(ev->event), ev->event, ev->status, cm_id);

	/* 
		1)  LID와 같은 addr을 얻는다
		2)	LID로 향하는 경로를 탐색한다
		3)	Connection을 established 한다
	*/
	switch(ev->event) {
		case RDMA_CM_EVENT_ADDR_RESOLVED:
			cm_error = sswap_rdma_addr_resolved(queue);
			break;
		case RDMA_CM_EVENT_ROUTE_RESOLVED:
			cm_error = sswap_rdma_route_resolved(queue, &ev->param.conn);
			break;
		case RDMA_CM_EVENT_ESTABLISHED:
			queue->cm_error = sswap_rdma_conn_established(queue);
			/* connection이 established 되고 나서 complete를 수행한다 */
			/* error가 나는 부분이 sswap_rdma_route_resolved에서 return을 안해서 그런거 같다 */
			complete(&queue->cm_done);
			return 0;
		case RDMA_CM_EVENT_REJECTED:
			pr_err("connection rejected\n");
			break;
		case RDMA_CM_EVENT_ADDR_ERROR:
		case RDMA_CM_EVENT_ROUTE_ERROR:
		case RDMA_CM_EVENT_CONNECT_ERROR:
		case RDMA_CM_EVENT_UNREACHABLE:
			pr_err("CM error event %d\n", ev->event);
			cm_error = -ECONNRESET;
			break;
		case RDMA_CM_EVENT_DISCONNECTED:
		case RDMA_CM_EVENT_ADDR_CHANGE:
		case RDMA_CM_EVENT_TIMEWAIT_EXIT:
			pr_err("CM connection closed %d\n", ev->event);
			break;
		case RDMA_CM_EVENT_DEVICE_REMOVAL:
			break;
		default:
			pr_err("CM unexpected event: %d\n", ev->event);
			break;
	}
	if(cm_error) {
		queue->cm_error = cm_error;
		complete(&queue->cm_done);
	}
	return 0;
}

static int sswap_rdma_init_queue(struct sswap_rdma_ctrl *ctrl,
    int idx)
{
  struct rdma_queue *queue;
  int ret;

  pr_info("start: %s\n", __FUNCTION__);

  queue = &ctrl->queues[idx];
  queue->ctrl = ctrl;
  init_completion(&queue->cm_done);
  atomic_set(&queue->pending, 0);
  spin_lock_init(&queue->cq_lock);
  queue->qp_type = get_queue_type(idx);

  queue->cm_id = rdma_create_id(&init_net, sswap_rdma_cm_handler, queue,
      RDMA_PS_TCP, IB_QPT_RC);
  if (IS_ERR(queue->cm_id)) {
    pr_err("failed to create cm id: %ld\n", PTR_ERR(queue->cm_id));
    return -ENODEV;
  }

  queue->cm_error = -ETIMEDOUT;

  /* 
	 srcaddr, dstaddr을 이용하여, addr을 resolve한다 
	 등록해 놓은 sswap_rdma_cm_handler가 불린다 
  */
  ret = rdma_resolve_addr(queue->cm_id, &ctrl->srcaddr, &ctrl->addr,
      CONNECTION_TIMEOUT_MS);
  if (ret) {
    pr_err("rdma_resolve_addr failed: %d\n", ret);
    goto out_destroy_cm_id;
  }

  ret = sswap_rdma_wait_for_cm(queue);
  if (ret) {
    pr_err("sswap_rdma_wait_for_cm failed\n");
    goto out_destroy_cm_id;
  }

  pr_info("end: %s\n", __FUNCTION__);
  return 0;

out_destroy_cm_id:
  rdma_destroy_id(queue->cm_id);
  return ret;
}

static void sswap_rdma_stop_queue(struct rdma_queue *q)
{
  rdma_disconnect(q->cm_id);
}

static void sswap_rdma_free_queue(struct rdma_queue *q)
{
  rdma_destroy_qp(q->cm_id);
  ib_free_cq(q->cq);
  rdma_destroy_id(q->cm_id);
}

static int sswap_rdma_init_queues(struct sswap_rdma_ctrl *ctrl)
{
  int ret, i;
  for (i = 0; i < numqueues; ++i) {
    ret = sswap_rdma_init_queue(ctrl, i);
    if (ret) {
      pr_err("failed to initialized queue: %d\n", i);
      goto out_free_queues;
    }
  }

  return 0;

out_free_queues:
  for (i--; i >= 0; i--) {
    sswap_rdma_stop_queue(&ctrl->queues[i]);
    sswap_rdma_free_queue(&ctrl->queues[i]);
  }

  return ret;
}

static int sswap_rdma_parse_ipaddr(struct sockaddr_in *saddr, char *ip)
{
  u8 *addr = (u8 *)&saddr->sin_addr.s_addr;
  size_t buflen = strlen(ip);

  pr_info("start: %s\n", __FUNCTION__);

  if (buflen > INET_ADDRSTRLEN)
    return -EINVAL;
  if (in4_pton(ip, buflen, addr, '\0', NULL) == 0)
    return -EINVAL;
  saddr->sin_family = AF_INET;
  return 0;
}

static int sswap_rdma_create_ctrl(struct sswap_rdma_ctrl **c)
{
  int ret;
  struct sswap_rdma_ctrl *ctrl;
  pr_info("will try to connect to %s:%d\n", serverip, serverport);

  *c = kzalloc(sizeof(struct sswap_rdma_ctrl), GFP_KERNEL);
  if (!*c) {
    pr_err("no mem for ctrl\n");
    return -ENOMEM;
  }
  ctrl = *c;
  /* cpu 개수 * 3 */
  ctrl->queues = kzalloc(sizeof(struct rdma_queue) * numqueues, GFP_KERNEL);
  
  ret = sswap_rdma_parse_ipaddr(&(ctrl->addr_in), serverip);
  if (ret) {
    pr_err("sswap_rdma_parse_ipaddr failed: %d\n", ret);
    return -EINVAL;
  }
  ctrl->addr_in.sin_port = cpu_to_be16(serverport);
  
  ret = sswap_rdma_parse_ipaddr(&(ctrl->srcaddr_in), clientip);
  if (ret) {
    pr_err("sswap_rdma_parse_ipaddr failed: %d\n", ret);
    return -EINVAL;
  }
  /* no need to set the port on the srcaddr */

  return sswap_rdma_init_queues(ctrl);
}

static void sswap_rdma_recv_remotemr_done(struct ib_cq *cq, struct ib_wc *wc)
{
  struct rdma_req *qe =
    container_of(wc->wr_cqe, struct rdma_req, cqe);
  
  struct rdma_queue *q = cq->cq_context;
  struct sswap_rdma_ctrl *ctrl = q->ctrl;
  struct ib_device *ibdev = q->ctrl->rdev->dev;

  if (unlikely(wc->status != IB_WC_SUCCESS)) {
    pr_err("sswap_rdma_recv_done status is not success\n");
    return;
  }
  /* mapping 해놓은 후에는 unmapping 해놓는다. */ 
  ib_dma_unmap_single(ibdev, qe->dma, sizeof(struct sswap_rdma_memregion),
              DMA_FROM_DEVICE);
  pr_info("servermr baseaddr=%llx, key=%u\n", ctrl->servermr.baseaddr,
      ctrl->servermr.key);
  complete_all(&qe->done);
}

static int sswap_rdma_post_recv(struct rdma_queue *q, struct rdma_req *qe,
  size_t bufsize)
{
  struct ib_recv_wr *bad_wr;
  struct ib_recv_wr wr = {};
  struct ib_sge sge;
  int ret;
  /* dma 주소를 알려준다 */
  sge.addr = qe->dma;
  sge.length = bufsize;
  /*
	 ib_alloc_pd를 통해 받은 lkey를 사용해야 memory region에 접근이 가능하다 
  */
  sge.lkey = q->ctrl->rdev->pd->local_dma_lkey;
  /*
	 wr_cqe에 알맞은 cqe를 넣어놓아서 done에 연결된 함수를 실행한다
  */
  wr.next    = NULL;
  wr.wr_cqe  = &qe->cqe;
  wr.sg_list = &sge;
  wr.num_sge = 1;
  /*
    [분석] : work recv queue에 일을 넣어놓는다.
  */
  ret = ib_post_recv(q->qp, &wr, (const struct ib_recv_wr **)&bad_wr);
  if (ret) {
    pr_err("ib_post_recv failed: %d\n", ret);
  }
  return ret;
}

/************ malloc buffer / page *****************/

inline static int get_req_for_page(struct rdma_req **req, struct ib_device *dev,
                struct page *page, enum dma_data_direction dir)
{
  int ret;

  ret = 0;
  *req = kmem_cache_alloc(req_cache, GFP_ATOMIC);
  if (unlikely(!req)){
    pr_err("no memory for req\n");
    ret = -ENOMEM;
    goto out;
  }

  (*req)->page = page;
  init_completion(&(*req)->done);
  /*
    request work를 만드는데, page랑 dma를 mapping 한다
	여기서 보면 page에 바로 dma하는 것을 알 수 있다
  */
  (*req)->dma = ib_dma_map_page(dev, page, 0, PAGE_SIZE, dir);
  if (unlikely(ib_dma_mapping_error(dev, (*req)->dma))) {
    pr_err("ib_dma_mapping_error\n");
    ret = -ENOMEM;
    kmem_cache_free(req_cache, req);
    goto out;
  }
  /*
    최종적으로 device와, page를 매핑시킨다.
  */
  ib_dma_sync_single_for_device(dev, (*req)->dma, PAGE_SIZE, dir);
out:
  return ret;
}

/* the buffer needs to come from kernel (not high memory) */
inline static int get_req_for_buf(struct rdma_req **req, struct ib_device *dev,
                void *buf, size_t size,
                enum dma_data_direction dir)
{
  int ret;

  ret = 0;
  *req = kmem_cache_alloc(req_cache, GFP_ATOMIC);
  if (unlikely(!req)) {
    pr_err("no memory for req\n");
    ret = -ENOMEM;
    goto out;
  }

  init_completion(&(*req)->done);
  /*
    buf에 해당하는 dma 주소를 할당받는다
  */
  (*req)->dma = ib_dma_map_single(dev, buf, size, dir);
  if (unlikely(ib_dma_mapping_error(dev, (*req)->dma))) {
    pr_err("ib_dma_mapping_error\n");
    ret = -ENOMEM;
    kmem_cache_free(req_cache, req);
    goto out;
  }
  /*
	dma_sync_single_for_device() is required to allow the device to access the buffer again
  */
  ib_dma_sync_single_for_device(dev, (*req)->dma, size, dir);
out:
  return ret;
}

inline static void sswap_rdma_wait_completion(struct ib_cq *cq,
                          struct rdma_req *qe)
{
  ndelay(1000);
  while (!completion_done(&qe->done)) {
    ndelay(250);
    ib_process_cq_direct(cq, 1);
  }
}

static int sswap_rdma_recv_remotemr(struct sswap_rdma_ctrl *ctrl)
{
  struct rdma_req *qe;
  int ret;
  struct ib_device *dev;

  pr_info("start: %s\n", __FUNCTION__);
  dev = ctrl->rdev->dev;

  /* server의 memory region을 받아온다 */
  ret = get_req_for_buf(&qe, dev, &(ctrl->servermr), sizeof(ctrl->servermr),
            DMA_FROM_DEVICE);
  if (unlikely(ret))
    goto out;

  qe->cqe.done = sswap_rdma_recv_remotemr_done;

  ret = sswap_rdma_post_recv(&(ctrl->queues[0]), qe, sizeof(struct sswap_rdma_memregion));

  if (unlikely(ret))
    goto out_free_qe;

  /* this delay doesn't really matter, only happens once */
  /* 다른 곳에서 complete_all()가 호출될 때까지 기다린다. */
  sswap_rdma_wait_completion(ctrl->queues[0].cq, qe);

out_free_qe:
  kmem_cache_free(req_cache, qe);
out:
  return ret;
}

inline enum qp_type get_queue_type(unsigned int idx)
{
  // numcpus = 8
  if (idx < numcpus)
    return QP_READ_SYNC;
  else if (idx < numcpus * 2)
    return QP_READ_ASYNC;
  else if (idx < numcpus * 3)
    return QP_WRITE_SYNC;

  BUG();
  return QP_READ_SYNC;
}

/************ common part *************/
inline struct rdma_queue *sswap_rdma_get_queue(unsigned int cpuid, enum qp_type type)
{
	BUG_ON(gctrl == NULL);

	switch(type) {
		case QP_READ_SYNC:
			return &gctrl->queues[cpuid];
		case QP_READ_ASYNC:
			return &gctrl->queues[cpuid + numcpus];
		case QP_WRITE_SYNC:
			return &gctrl->queues[cpuid + numcpus * 2];
		default:
			BUG();
	};
}

static inline int poll_target(struct rdma_queue *q, int target)
{
  unsigned long flags;
  int completed = 0;

  while (completed < target && atomic_read(&q->pending) > 0) {
    spin_lock_irqsave(&q->cq_lock, flags);
    completed += ib_process_cq_direct(q->cq, target - completed);
    spin_unlock_irqrestore(&q->cq_lock, flags);
    cpu_relax();
  }

  return completed;
}

static inline int drain_queue(struct rdma_queue *q)
{
  unsigned long flags;

  while (atomic_read(&q->pending) > 0) {
    spin_lock_irqsave(&q->cq_lock, flags);
    ib_process_cq_direct(q->cq, 16);
    spin_unlock_irqrestore(&q->cq_lock, flags);
    cpu_relax();
  }

  return 1;
}

/************ rdma write **************/
inline static int sswap_rdma_post_rdma(struct rdma_queue *q, struct rdma_req *qe,
  struct ib_sge *sge, u64 roffset, enum ib_wr_opcode op)
{
  struct ib_send_wr *bad_wr;
  struct ib_rdma_wr rdma_wr = {};
  int ret;

  BUG_ON(qe->dma == 0);
  
  sge->addr = qe->dma;
  sge->length = qe->size;
  sge->lkey = q->ctrl->rdev->pd->local_dma_lkey;

  /* TODO: add a chain of WR, we already have a list so should be easy
   * to just post requests in batches */
  rdma_wr.wr.next    = NULL;
  rdma_wr.wr.wr_cqe  = &qe->cqe;
  rdma_wr.wr.sg_list = sge;
  rdma_wr.wr.num_sge = 1;
  rdma_wr.wr.opcode  = op;
  rdma_wr.wr.send_flags = IB_SEND_SIGNALED;
  rdma_wr.remote_addr = q->ctrl->servermr.baseaddr + roffset;
  rdma_wr.rkey = q->ctrl->servermr.key;

  atomic_inc(&q->pending);
  /*
    [분석] : rdma_write_queue에 넣어놓는다.
  */
  ret = ib_post_send(q->qp, &rdma_wr.wr, (const struct ib_send_wr **)&bad_wr);
  if (unlikely(ret)) {
    pr_err("ib_post_send failed: %d\n", ret);
  }

  return ret;
}

static void sswap_rdma_write_done(struct ib_cq *cq, struct ib_wc *wc)
{
  struct rdma_req *req =
    container_of(wc->wr_cqe, struct rdma_req, cqe);
  
  struct rdma_queue *q = cq->cq_context;
  struct ib_device *ibdev = q->ctrl->rdev->dev;

  if (unlikely(wc->status != IB_WC_SUCCESS)) {
    pr_err("sswap_rdma_write_done status is not success, it is=%d\n", wc->status);
    //q->write_error = wc->status;
  }

  ib_dma_unmap_page(ibdev, req->dma, PAGE_SIZE, DMA_TO_DEVICE);
  /*
	 if success we write the page to user for overwrite the page already existed
  */
  /******** add ********/
  /* If we success, we increase tail counter for success */
  atomic_tail_inc();
  /*********************/
  atomic_dec(&q->pending);
  kmem_cache_free(req_cache, req);
}

static inline int write_queue_add(struct rdma_queue *q, struct page *page,
                  u64 roffset)
{
  struct rdma_req *req;
  struct ib_device *dev = q->ctrl->rdev->dev;
  struct ib_sge sge = {};
  int ret, inflight;

  while ((inflight = atomic_read(&q->pending)) >= QP_MAX_SEND_WR - 8) {
    BUG_ON(inflight > QP_MAX_SEND_WR);
    poll_target(q, 2048);
    pr_info_ratelimited("back pressure writes");
  }

  ret = get_req_for_page(&req, dev, page, DMA_TO_DEVICE);
  if (unlikely(ret))
    return ret;

  req->cqe.done = sswap_rdma_write_done;
  ret = sswap_rdma_post_rdma(q, req, &sge, roffset, IB_WR_RDMA_WRITE);

  return ret;
}

int sswap_rdma_write(uint64_t page_address, u64 offset, uint64_t ts, char *buf)
{
	int ret;
	struct rdma_queue *q;
	struct page *page = rdma_buf[atomic_read(&buf_info.tail)].page;

	VM_BUG_ON_PAGE(!PageSwapCache(page), page);
	/********* add **********/
	memcpy(page_address(page), buf, PAGE_SIZE);
	rdma_buf[atomic_read(&buf_info.tail)].host_page = page_address;
	rdma_buf[atomic_read(&buf_info.tail)].ts = ts;
	/***********************/
	q = sswap_rdma_get_queue(smp_processor_id(), QP_WRITE_SYNC);
	ret = write_queue_add(q, page, offset);
	BUG_ON(ret);
	drain_queue(q);
	return ret;
}

void host_rdma_write(struct page *page, uint64_t ts)
{
	prefetch_lru_drain_wrapper((uint64_t)page_address(page), 2);
	
	write_rdma_buf[atomic_read(&write_buf_info.tail)].page = page;
	write_rdma_buf[atomic_read(&write_buf_info.tail)].host_page = (uint64_t)page_address(page);
	write_rdma_buf[atomic_read(&write_buf_info.tail)].ts = ts;
	atomic_tail_inc_write();
}

/*************** rdma read *****************/
static void sswap_rdma_read_done(struct ib_cq *cq, struct ib_wc *wc)
{
  struct rdma_req *req =
    container_of(wc->wr_cqe, struct rdma_req, cqe);
  struct rdma_queue *q = cq->cq_context;
  struct ib_device *ibdev = q->ctrl->rdev->dev;

  if (unlikely(wc->status != IB_WC_SUCCESS))
    pr_err("sswap_rdma_read_done status is not success, it is=%d\n", wc->status);
  ib_dma_unmap_page(ibdev, req->dma, req->size, DMA_FROM_DEVICE);
 
  if(req->is_page) {
	SetPageUptodate(req->page);
	unlock_page(req->page);
  }
  complete(&req->done);
  atomic_dec(&q->pending);
  kmem_cache_free(req_cache, req);
  atomic_tail_inc();
}

static inline int begin_read(struct rdma_queue *q, struct page *page,
                 u64 roffset)
{
  struct rdma_req *req;
  struct ib_device *dev = q->ctrl->rdev->dev;
  struct ib_sge sge = {};
  int ret, inflight;

  /* back pressure in-flight reads, can't send more than
   * QP_MAX_SEND_WR at a time */
  while ((inflight = atomic_read(&q->pending)) >= QP_MAX_SEND_WR) {
    BUG_ON(inflight > QP_MAX_SEND_WR); /* only valid case is == */
    poll_target(q, 8);
    pr_info_ratelimited("back pressure happened on reads");
  }
  /*
    device와 page를 mapping 시키기 위한 코드이다.
  */
  ret = get_req_for_page(&req, dev, page, DMA_TO_DEVICE);
  if (unlikely(ret))
    return ret;

  req->cqe.done = sswap_rdma_read_done;
  /*** add ***/
  req->size = PAGE_SIZE;
  req->is_page = true;
  /**********/
  ret = sswap_rdma_post_rdma(q, req, &sge, roffset, IB_WR_RDMA_READ);
  return ret;
}

static inline int begin_read_buf(struct rdma_queue *q, void *buf, size_t size, u64 roffset)
{
	struct rdma_req *req;
	struct ib_device *dev = q->ctrl->rdev->dev;
	struct ib_sge sge = {};
	int ret, inflight;

	while ((inflight = atomic_read(&q->pending)) >= QP_MAX_SEND_WR) {
		BUG_ON(inflight > QP_MAX_SEND_WR);
		poll_target(q, 8);
		pr_info_ratelimited("back pressure happened on reads");
	}

	ret = get_req_for_buf(&req, dev, buf, size, DMA_TO_DEVICE);
	if (unlikely(ret))
		return ret;

	req->cqe.done = sswap_rdma_read_done;
	/*** add ***/
	req->size = size;
	req->is_page = false;
	/**********/
	ret = sswap_rdma_post_rdma(q, req, &sge, roffset, IB_WR_RDMA_READ);
	return ret;
}

// SmartNIC에서 이 함수를 이용해서 page에 대한 read 요청을 보낸다
// Page까지 보내줄 필요가 없다. => rdma_buf의 page가 dma를 통해 자동으로 데이터를 받게 만든다
// SmartNIC에서 이 함수를 이용해서 page에 대한 read 요청을 보낸다
// Page까지 보내줄 필요가 없다. => rdma_buf의 page가 dma를 통해 자동으로 데이터를 받게 만든다
int host_rdma_read_sync(struct page *page, u64 roffset)
{
  struct rdma_queue *q;
  int ret;

  VM_BUG_ON_PAGE(!PageSwapCache(page), page);
  VM_BUG_ON_PAGE(!PageLocked(page), page);
  VM_BUG_ON_PAGE(PageUptodate(page), page);

  q = sswap_rdma_get_queue(smp_processor_id(), QP_READ_SYNC);
  ret = begin_read(q, page, roffset);
  return ret;
}

int sswap_rdma_read_sync(uint64_t page_address, u64 roffset, uint64_t ts)
{
  struct rdma_queue *q;
  int ret;
  struct page *page = rdma_buf[atomic_read(&buf_info.tail)].page;

  VM_BUG_ON_PAGE(!PageSwapCache(page), page);
  VM_BUG_ON_PAGE(!PageLocked(page), page);
  VM_BUG_ON_PAGE(PageUptodate(page), page);
  
  rdma_buf[atomic_read(&buf_info.tail)].host_page = page_address;
  rdma_buf[atomic_read(&buf_info.tail)].ts = ts;
  q = sswap_rdma_get_queue(smp_processor_id(), QP_READ_SYNC);
  ret = begin_read(q, page, roffset);
  return ret;
}

int sswap_rdma_read_async(uint64_t page_address, u64 roffset, uint64_t ts)
{
  struct rdma_queue *q;
  int ret;
  struct page *page = rdma_buf[atomic_read(&buf_info.tail)].page;

  VM_BUG_ON_PAGE(!PageSwapCache(page), page);
  VM_BUG_ON_PAGE(!PageLocked(page), page);
  VM_BUG_ON_PAGE(PageUptodate(page), page);
  
  rdma_buf[atomic_read(&buf_info.tail)].host_page = page_address;
  rdma_buf[atomic_read(&buf_info.tail)].ts = ts;
  q = sswap_rdma_get_queue(smp_processor_id(), QP_READ_ASYNC);
  ret = begin_read(q, page, roffset);
  return ret;
}

int sswap_rdma_read_sync_buf(void *buf, size_t size, u64 roffset)
{
  struct rdma_queue *q;
  int ret;
	
  q = sswap_rdma_get_queue(smp_processor_id(), QP_READ_SYNC);
  ret = begin_read_buf(q, buf, size, roffset);
  return ret;
}

int sswap_rdma_read_async_buf(void *buf, size_t size, u64 roffset)
{
  struct rdma_queue *q;
  int ret;
  
  q = sswap_rdma_get_queue(smp_processor_id(), QP_READ_ASYNC);
  ret = begin_read_buf(q, buf, size, roffset);
  return ret;
}
/*****************************************************/

/*********** rdma init *******************************/
int rdma_init(void)
{
	int ret;

	allow_signal(SIGKILL);
	pr_info("start: %s\n", __FUNCTION__);
	pr_info("* RDMA INIT *");

	// <linux/cpumask.h>
	// numcpus = num_online_cpus();
	numcpus = 8;
	numqueues = numcpus * 3;

	req_cache = kmem_cache_create("sswap_req_cache", sizeof(struct rdma_req), 0, SLAB_TEMPORARY | SLAB_HWCACHE_ALIGN, NULL);
	if(!req_cache) {
		pr_err("no memory for cache allocation\n");
		return -ENOMEM;
	}

	ib_register_client(&sswap_rdma_ib_client);

	ret = sswap_rdma_create_ctrl(&gctrl);
	if (ret) {
		pr_err("could not create ctrl\n");
		ib_unregister_client(&sswap_rdma_ib_client);
		return -ENODEV;
	}
	
	ret = sswap_rdma_recv_remotemr(gctrl);
	if (ret) {
		pr_err("could not setup remote memory region\n");
		ib_unregister_client(&sswap_rdma_ib_client);
		return -ENODEV;
	}

	pr_info("ctrl is ready for reqs\n");
	return 0;
}

/*************************************************/
void atomic_head_inc(void)
{
	atomic_set(&buf_info.head, (atomic_read(&buf_info.head) + 1) % buf_info.size);
	if(atomic_read(&buf_info.head) == 0) 
		atomic_inc(&buf_info.head_round);
}

void atomic_tail_inc(void)
{
	atomic_set(&buf_info.tail, (atomic_read(&buf_info.tail) + 1) % buf_info.size);
	if(atomic_read(&buf_info.tail) == 0)
		atomic_inc(&buf_info.tail_round);
}

void atomic_head_inc_write(void)
{
    atomic_set(&write_buf_info.head, (atomic_read(&write_buf_info.head) + 1) % write_buf_info.size);
    if(atomic_read(&write_buf_info.head) == 0)
        atomic_inc(&write_buf_info.head_round);
}

void atomic_tail_inc_write(void)
{
    atomic_set(&write_buf_info.tail, (atomic_read(&write_buf_info.tail) + 1) % write_buf_info.size);
    if(atomic_read(&write_buf_info.tail) == 0)
        atomic_inc(&write_buf_info.tail_round);
}

void atomic_write_idx_inc(void)
{
	atomic_set(&write_idx, (atomic_read(&write_idx) + 1) % write_buf_info.size);
}

MODULE_LICENSE("GPL");
