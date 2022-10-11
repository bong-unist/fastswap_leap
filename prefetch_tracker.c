
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/tty.h>
#include <linux/kthread.h>

#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/ptrace.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <uapi/linux/fs.h>

#include <linux/errno.h>
#include <linux/types.h>

#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/in.h>

#include <linux/delay.h>
#include <linux/syscalls.h>
#include <linux/frontswap.h>

#include "ksocket.h"
#include "prefetch_queue.h"
#include "prefetch_mmap.h"
#include "prefetch_rdma.h"

#define MODULE_NAME "server_tracker"
#define INADDR_SEND INADDR_LOOKBACK

struct kthread_t
{
	struct task_struct *thread, *write_thread;
	ksocket_t sockfd_srv, sockfd_cli;
	struct sockaddr_in addr_srv, addr_cli;
	int running;
	int write_running;
};

struct kthread_t *kthread = NULL;
struct kthread_t *rdma_kthread = NULL;

const unsigned int MINOR_BASE = 0;
const unsigned int MINOR_NUM = 1;
unsigned int mmapdev_major;
struct cdev *mmapdev_cdev = NULL;
struct class *mmapdev_class = NULL;
extern int *data;
extern atomic_t counter;
extern atomic_t send_metadata;

/***************************************/
extern struct rdma_buf rdma_buf[PAGE_CNT];
extern struct buf_info buf_info;
extern struct rdma_buf write_rdma_buf[PAGE_CNT];
extern struct buf_info write_buf_info;
extern DECLARE_HASHTABLE(h_prefetch_data, 6);
extern DECLARE_HASHTABLE(h_metadata_prefetch_data, 6);
extern DECLARE_HASHTABLE(h_write_prefetch_data, 6);

extern atomic_t write_idx;
extern struct write_prefetch_data write_addr[PAGE_CNT]; 
/***************************************/

struct prefetch_request_list *prefetch_request_list;
struct list_head *head;
static struct mutex my_mutex;

/***************************************/
typedef enum HASHTABLE_TYPE {
	H_PREFETCH_DATA,
	H_METADATA_PREFETCH_DATA,
	H_WRITE_PREFETCH_DATA
} HASHTABLE_TYPE;

int DEFAULT_PORT;
unsigned int custom_prefetch;
static char socket_serverip[INET_ADDRSTRLEN];
module_param(DEFAULT_PORT, int, 0644);
module_param(custom_prefetch, uint, 0644);
module_param_string(socket_sip, socket_serverip, INET_ADDRSTRLEN, 0644);
//우선 지금은 간단한 socket 통신을 위한 API를 만든다.
//LEAP를 SMARTNIC안에 넣게 되면, IS_rdma_write와 같은 함수를 만드는 것이 필요하다

static inline long myclock(void)
{
	return ktime_get_ns();
}

static int ksocket_server_start(void)
{
	char *tmp = NULL;
	int addr_len;

	kthread->sockfd_srv = kthread->sockfd_cli = NULL;
	memset(&kthread->addr_srv, 0, sizeof(kthread->addr_srv));
	memset(&kthread->addr_cli, 0, sizeof(kthread->addr_cli));
	kthread->addr_srv.sin_family = AF_INET;
	kthread->addr_srv.sin_port = htons(DEFAULT_PORT);
	kthread->addr_srv.sin_addr.s_addr = INADDR_ANY;
	addr_len = sizeof(struct sockaddr_in);

	kthread->sockfd_srv = ksocket(AF_INET, SOCK_STREAM, 0);
	printk("sockfd_srv = 0x%p\n", kthread->sockfd_srv);
	if(kthread->sockfd_srv == NULL)
	{
		printk("socket failed\n");
		return -1;
	}
	if(kbind(kthread->sockfd_srv, (struct sockaddr *)&kthread->addr_srv, addr_len) < 0)
	{
		printk("bind failed\n");
		return -1;
	}
	if(klisten(kthread->sockfd_srv, 10) < 0)
	{
		printk("listen failed\n");
		return -1;
	}
	kthread->sockfd_cli = kaccept(kthread->sockfd_srv, (struct sockaddr *)&kthread->addr_cli, &addr_len);
	if(kthread->sockfd_cli == NULL)
	{
		printk("accept failed\n");
		return -1;
	}
	else printk("sockfd_cli = 0x%p\n", kthread->sockfd_cli);

	tmp = inet_ntoa(&kthread->addr_cli.sin_addr);
	if(tmp == NULL) 
	{
		printk("inet_ntoa failed\n");
		return -1;
	}
	printk("got connected from : %s %d\n", tmp, ntohs(kthread->addr_cli.sin_port));
	kfree(tmp);

	printk("try to send data\n");
	ksocket_send(kthread->sockfd_cli, (struct sockaddr_in *)&kthread->addr_cli, 0, 0, rdma_buf[0].page, (uint64_t)myclock());
	printk("success send data\n");
	return 0;
}

int ksocket_client_start(void)
{
	u8 *addr;
	size_t buflen;
	int addr_len;

	kthread->sockfd_cli = NULL;
	memset(&kthread->addr_srv, 0, sizeof(kthread->addr_srv));
	kthread->addr_srv.sin_family = AF_INET;
	kthread->addr_srv.sin_port = htons(DEFAULT_PORT);
	addr_len = sizeof(struct sockaddr_in);

	buflen = strlen(socket_serverip);
	if(buflen > INET_ADDRSTRLEN) 
	{
		printk(KERN_ERR "buflen > INET_ADDRSTRLEN\n");
		return -1;
	}
	addr = (u8*)&kthread->addr_srv.sin_addr.s_addr;
	if(in4_pton(socket_serverip, buflen, addr, '\0', NULL) == 0)
	{
		printk(KERN_ERR "in4_pton failed\n");
		return -1;
	}

	kthread->sockfd_cli = ksocket(AF_INET, SOCK_STREAM, 0);
	printk("sockfd_cli = 0x%p\n", kthread->sockfd_cli);
	if (kthread->sockfd_cli == NULL)
	{
		printk("socket failed\n");
		return -1;
	}
	if (kconnect(kthread->sockfd_cli, (struct sockaddr*)&kthread->addr_srv, addr_len) > 0)
	{
		printk("connect failed\n");
		return -1;
	}

	printk("connected to %d\n", ntohs(kthread->addr_srv.sin_port));
	return 0;
}

static void recv_request(void)
{
	struct prefetch_request *request = NULL;
	int size, err;
	
	mutex_init(&my_mutex);
	mutex_lock(&my_mutex);
	current->flags |= PF_NOFREEZE;
	allow_signal(SIGKILL);
	kthread->running = 0;
	mutex_unlock(&my_mutex);

	request = (struct prefetch_request *)kmalloc(sizeof(struct prefetch_request), GFP_KERNEL);
	if (request == NULL) {
		printk(KERN_ERR "recv_request kmalloc() failed\n");
		return;
	}

	kthread->running = 1;

	while(true) {
		if(kthread->sockfd_cli == NULL) {
			printk("not connected\n");
			continue;
		}
		if(kthread->running == 0) {
			printk("end :%s\n", __FUNCTION__);
			break;
		}
		memset(request, 0, sizeof(struct prefetch_request));
		size = ksocket_recv(kthread->sockfd_cli, (struct sockaddr_in *)&kthread->addr_cli, request);

		if(signal_pending(current)) break;
		if(size <= 0) {
			if(size == -11) continue;
			if(size == 0) printk("Disconnected\n");
			printk(KERN_ERR "error getting stream, sock_recvmsg error = %d\n", size);
			kthread->running = 0;
			break;
		}
		else if(size < sizeof(struct prefetch_request)) {
			pr_info("Not recv completed data\n");
		}
		else {
			printk(KERN_INFO "received %d bytes\n", size);
			printk("data = %u, %ld, %llu\n", request->type, request->pageid, request->page_address);
			
			if(request->type == 1) {
                err = sswap_rdma_read_sync(request->page_address, (request->pageid << PAGE_SHIFT), request->ts);
                if(err < 0) printk(KERN_WARNING MODULE_NAME": error sswap_rdma_read_sync\n");
            }
            else if(request->type == 2) {
				write_addr[atomic_read(&write_idx)].addr = request->page_address;
				write_addr[atomic_read(&write_idx)].offset = (request->pageid << PAGE_SHIFT);
				write_addr[atomic_read(&write_idx)].ts = request->ts;
				atomic_write_idx_inc();
            }
            else if(request->type == 3) {
                atomic_set(&send_metadata, request->page_address);
            }
		}
	}

	kfree(request);
}

static void write_request(void)
{
	struct prefetch_data *pdata;
	int i;
	pr_info("start: %s\n", __FUNCTION__);

	mutex_init(&my_mutex);
	mutex_lock(&my_mutex);
	current->flags |= PF_NOFREEZE;
	allow_signal(SIGKILL);
	kthread->write_running = 0;
	mutex_unlock(&my_mutex);

	kthread->write_running = 1;
	
	while(true) {
		if(kthread->write_running == 0) {
			pr_info("end: %s\n", __FUNCTION__);
			return;
		}
		for(i = 0 ; i < PAGE_CNT ; i++) {
			if (write_addr[i].addr != 0) {
				hash_for_each_possible(h_write_prefetch_data, pdata, my_hash_list, write_addr[i].addr) {
					sswap_rdma_write(write_addr[i].addr, write_addr[i].offset, write_addr[i].ts, pdata->buf);
					write_addr[i].addr = write_addr[i].offset = write_addr[i].ts = 0;
					hash_del(&pdata->my_hash_list);
				}
			}
		}
	}

	pr_info("end: %s\n", __FUNCTION__);
}

int request_queue_init(void)
{
	head = kmalloc(sizeof(struct list_head *), GFP_KERNEL);
	if (head == NULL) {
		pr_err("%s : kmalloc failed\n", __FUNCTION__);
		return -1;
	}
	INIT_LIST_HEAD(head);
	return 0;
}

static int mmap_device_init(void)
{
	int alloc_ret = 0, cdev_err = 0;
	dev_t dev;

	printk(KERN_WARNING "start: %s\n", __FUNCTION__);
	mmapdev_cdev = cdev_alloc();
	alloc_ret = alloc_chrdev_region(&dev, MINOR_BASE, MINOR_NUM, DEV_NAME);
	if (alloc_ret != 0) {
		printk(KERN_ERR "alloc_chrdev_region = %d\n", alloc_ret);
		return -1;
	}

	mmapdev_major = MAJOR(dev);
	dev = MKDEV(mmapdev_major, MINOR_BASE);

	cdev_init(mmapdev_cdev, &mmap_fops);
	mmapdev_cdev->owner = THIS_MODULE;

	printk(KERN_WARNING "cdev_add\n");
	cdev_err = cdev_add(mmapdev_cdev, dev, MINOR_NUM);
	if (cdev_err != 0) {
		printk(KERN_ERR "cdev_add = %d\n", cdev_err);
		goto OUT2;
	}

	printk(KERN_WARNING "class create\n");
	mmapdev_class = class_create(THIS_MODULE, "mmap_device3");
	if (IS_ERR(mmapdev_class)) {
		printk(KERN_ERR "class_create failed\n");
		goto OUT;
	}

	printk(KERN_WARNING "device_create\n");
	device_create(mmapdev_class, NULL, MKDEV(mmapdev_major, MINOR_BASE), NULL, DEV_NAME);
	data = vmalloc(DATA_SIZE);
	if (data == NULL) {
		printk(KERN_ERR "vmalloc failed\n");
		goto OUT;
	}
	memset(data, 0, DATA_SIZE);
	printk(KERN_WARNING "end: %s\n", __FUNCTION__);
	return 0;

OUT:
	cdev_del(mmapdev_cdev);
OUT2:
	unregister_chrdev_region(dev, MINOR_NUM);
	return -1;
}

static int mmap_device_exit(void)
{
	dev_t dev = MKDEV(mmapdev_major, MINOR_BASE);
	if (mmapdev_class) device_destroy(mmapdev_class, dev);
	if (mmapdev_class) class_destroy(mmapdev_class);
	if (mmapdev_cdev) cdev_del(mmapdev_cdev);
	if (dev) unregister_chrdev_region(dev, MINOR_NUM);
	if(data) vfree(data);
	return 0;
}

static bool poll_data(struct page *page)
{
	long st = myclock(), et;
	bool find = false;
	struct prefetch_data *pdata;
	uint64_t addr = (uint64_t)page_address(page);

	while(!find) {
		hash_for_each_possible(h_prefetch_data, pdata, my_hash_list, addr) {
			memcpy(page_address(page), pdata->buf, PAGE_SIZE);
			find = true;
			break;
		}
		et = myclock();
		if(et - st >= 100000) break;
	}
	return find;
}
/*
	swapped-out되는 page들을 넘겨주기 때문에, 
	disk로 내리기 보다는 RAM 지역에 PAGE들을 남겨 놓기 위해
	frontswap_ops라는 interface를 사용한다
*/
static int sswap_store(unsigned type, pgoff_t pageid, struct page *page)
{
	int retval;
	uint64_t ts;
	pr_info("start :%s\n", __FUNCTION__);
	/* Before send write, check hash table and erase corresponding data invalid */
	ts = (uint64_t)myclock();
	host_rdma_write(page, ts); // kernel to user_process to send data to smartnic
	before_write(page, ts);
	/* need to send write request */
	retval = ksocket_send(kthread->sockfd_cli, &kthread->addr_cli, type, pageid, page, ts);
	pr_info("end :%s\n", __FUNCTION__);
	if(retval >= sizeof(struct prefetch_request)) return 0;
	else return -1;
}

static int sswap_load(unsigned type, pgoff_t pageid, struct page *page)
{
	return host_rdma_read_sync(page, pageid << PAGE_SHIFT);
}

static int sswap_load_async(unsigned type, pgoff_t pageid, struct page *page)
{
	/* First, Find a Page in hash table */
	int retval;

	pr_info("start: %s\n", __FUNCTION__);
	/* send a read request */
	retval = ksocket_send(kthread->sockfd_cli, &kthread->addr_cli, type, pageid, page, (uint64_t)myclock());
	pr_info("end: %s\n", __FUNCTION__);

	if(retval >= sizeof(struct prefetch_request)) return 0;
	else return -1;
}

static int sswap_lookup_prefetch(pgoff_t pageid, struct page *page)
{
	struct prefetch_data *pdata;
	bool find = false;
	uint64_t addr = (uint64_t)page_address(page), ts;
	uint8_t hashtable_type;
	int retval;

	pr_info("start: %s\n", __FUNCTION__);

	hash_for_each_possible(h_write_prefetch_data, pdata, my_hash_list, addr) {
		find = true;
		addr = pdata->addr;
		ts = pdata->ts;
		hashtable_type = H_WRITE_PREFETCH_DATA;
		break;
	}

	hash_for_each_possible(h_prefetch_data, pdata, my_hash_list, addr) {
		if (find) {
			if (ts < pdata->ts) {
				addr = pdata->addr;
				ts = pdata->ts;
				hashtable_type = H_PREFETCH_DATA;
				hash_del(&pdata->my_hash_list);
			}
		} else {
			find = true;
			addr = pdata->addr;
			ts = pdata->ts;
			hashtable_type = H_PREFETCH_DATA;
		}
		break;
	}

	hash_for_each_possible(h_metadata_prefetch_data, pdata, my_hash_list, addr) {
		if (find) {
			if (ts >= pdata->ts) break; 
		} else {
			retval = ksocket_send(kthread->sockfd_cli, &kthread->addr_cli, 3, pageid, page, (uint64_t)myclock());
			if (retval <= 0) return (find = false);
			find = poll_data(page);
			// If not exist, HOST directly request RDMA Read Request.
			return find;
		}
	}

	if (find) {
		if (hashtable_type == H_WRITE_PREFETCH_DATA) {
			hash_for_each_possible(h_write_prefetch_data, pdata, my_hash_list, addr) {
				memcpy((void *)addr, pdata->buf, PAGE_SIZE);
				break;		
			}
		}
		else if(hashtable_type == H_PREFETCH_DATA) {
			hash_for_each_possible(h_prefetch_data, pdata, my_hash_list, addr) {
				memcpy((void *)addr, pdata->buf, PAGE_SIZE);
				break;
			}
		}
	}

	return (find ? 0 : -1);
}

static void sswap_invalidate_page(unsigned type, pgoff_t offset)
{
	return;
}

static void sswap_invalidate_area(unsigned type)
{
	pr_err("sswap_invalidate_area\n");
}

static void sswap_init(unsigned type)
{
	pr_info("sswap_init end\n");
}

static struct frontswap_ops sswap_frontswap_ops = {
	.init = sswap_init,
	.store = sswap_store,
	.load = sswap_load,
#ifdef HOST
	.load_async = sswap_load_async,
	.lookup_prefetch = sswap_lookup_prefetch,
#else
#endif
	.invalidate_page = sswap_invalidate_page,
	.invalidate_area = sswap_invalidate_area,
};

int ksocket_init(void)
{
	int i;
#ifdef HOST
	if (custom_prefetch) {
		pr_info("custom_prefetch set\n");
		init_swap_trend(32);
		set_custom_prefetch(custom_prefetch);
		pr_info("is_custom_prefetch = %lu\n", get_custom_prefetch());

	}
#endif

	printk(KERN_ALERT "init mmap_device\n");	
	if(mmap_device_init() == -1) {
		printk(KERN_WARNING "mmap_device_init() failed\n");
		return -ENOMEM;
	}

	printk(KERN_INFO "init kmalloc for transfer data between kernel and user\n");
	for(i = 0 ; i < PAGE_CNT ; i++) rdma_buf[i].page = alloc_page(GFP_KERNEL);
	atomic_set(&buf_info.head, 0);
	atomic_set(&buf_info.tail, 0);
	atomic_set(&buf_info.head_round, 0);
	atomic_set(&buf_info.tail_round, 0);
	buf_info.size = PAGE_CNT;

	atomic_set(&write_buf_info.head, 0);
	atomic_set(&write_buf_info.tail, 0);
	atomic_set(&write_buf_info.head_round, 0);
	atomic_set(&write_buf_info.tail_round, 0);
	atomic_set(&write_idx, 0);
	write_buf_info.size = PAGE_CNT;
	
	printk(KERN_INFO "init socket thread\n");
	kthread = kmalloc(sizeof(struct kthread_t), GFP_KERNEL);
	if (kthread == NULL) {
		printk(KERN_ERR "kthread kmalloc failed\n");
		return -ENOMEM;
	}
	memset(kthread, 0, sizeof(struct kthread_t));
	
	printk(KERN_INFO "init rdma thread\n");
	rdma_kthread = kmalloc(sizeof(struct kthread_t), GFP_KERNEL);
	if (rdma_kthread == NULL) {
		printk(KERN_ERR "rdma kthread kmalloc failed\n");
		return -ENOMEM;
	}
	memset(rdma_kthread, 0, sizeof(struct kthread_t));

#ifdef HOST
	printk(KERN_INFO "I'm host\n");
	printk(KERN_INFO "init_frontswap ops\n");
	frontswap_register_ops(&sswap_frontswap_ops);
	printk(KERN_INFO "init socket\n");
	if(ksocket_server_start() < 0) {
		printk(KERN_ERR "ksocket_server_start() failed\n");
		return -ENOMEM;
	}
#else
	if(request_queue_init() < 0)
		return -ENOMEM;

	printk(KERN_INFO "I'm client\n");
	printk(KERN_INFO "init for rdma request\n");
	rdma_kthread->thread = kthread_run((void *)rdma_init, NULL, MODULE_NAME);
	if(IS_ERR(rdma_kthread->thread)) {
		printk(KERN_ERR MODULE_NAME":unable to start rdma init\n");
		kfree(rdma_kthread);
		rdma_kthread = NULL;
		return -ENOMEM;
	}
	
	printk("ksocket_client_start() start\n");
	if (ksocket_client_start() < 0) {
		printk(KERN_ERR "ksocket_client_start() failed\n");
		return -ENOMEM;
	}
	
	// Here make thread to run recv_sockmsg()
	printk("recv_request() thread start\n");
	kthread->thread = kthread_run((void *)recv_request, NULL, MODULE_NAME);
	if(IS_ERR(kthread->thread)) {
		printk(KERN_INFO MODULE_NAME":unable to start kernel thread\n");
		kfree(kthread);
		kthread = NULL;
		return -ENOMEM;
	}
	
	printk("write_request() thread start\n");
	kthread->write_thread = kthread_run((void *)write_request, NULL, MODULE_NAME);
	if(IS_ERR(kthread->write_thread)) {
		printk(KERN_INFO":unable to start kernel thread\n");
		kfree(kthread);
		kthread = NULL;
		return -ENOMEM;
	}
	
#endif
	return 0;
}

void ksocket_exit(void)
{
	printk(KERN_WARNING "try mmap_device_exit\n");
	mmap_device_exit();
	printk(KERN_WARNING "success mmap_device_exit\n");
	
	if(rdma_kthread && rdma_kthread->thread) {
		printk(KERN_INFO "stop rdma_kthread->thread\n");
		kthread_stop(rdma_kthread->thread);
		rdma_kthread->thread = NULL;
	}
	if(kthread && kthread->running) {
		printk(KERN_INFO "stop kthread->thread\n");
		kthread->running = 0;
		//kthread_stop(kthread->thread);
		kthread->thread = NULL;
	}
	if(kthread && kthread->write_running) {
		printk(KERN_INFO "stop kthread->write_thread\n");
		kthread->write_running = 0;
		//kthread_stop(kthread->write_thread);
		kthread->write_thread = NULL;
	}
	if(kthread && kthread->sockfd_srv != NULL) {
		printk(KERN_INFO "sock_release sockfd_srv\n");
		sock_release(kthread->sockfd_srv);
		kthread->sockfd_srv = NULL;
	}
	if(kthread && kthread->sockfd_cli != NULL) {
		printk(KERN_INFO "sock_release sockfd_cli\n");
		sock_release(kthread->sockfd_cli);
		kthread->sockfd_cli = NULL;
	}

	ssleep(1);
	if(rdma_kthread) kfree(rdma_kthread);
	if(kthread) kfree(kthread);
	kthread = NULL;
	rdma_kthread = NULL;
	
	printk(KERN_INFO MODULE_NAME":module unloaded\n");
}

module_init(ksocket_init);
module_exit(ksocket_exit);

MODULE_DESCRIPTION("SmartNIC Tracker");
MODULE_LICENSE("GPL");













