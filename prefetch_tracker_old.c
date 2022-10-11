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

#include "prefetch_mmap.h"
#include "prefetch_rdma.h"

#define MODULE_NAME "server_tracker"
#define INADDR_SEND INADDR_LOOKBACK

struct kthread_t
{
	struct task_struct *thread;
	struct socket *sock;
	struct sockaddr_in addr, client;
	int running;
};

struct prefetch_request {
	unsigned type;
	pgoff_t pageid;
	uint64_t page_address;
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
extern DECLARE_HASHTABLE(h_prefetch_data, 6);
extern DECLARE_HASHTABLE(h_metadata_prefetch_data, 6);
/***************************************/

int DEFAULT_PORT;
static struct mutex my_mutex;

static char socket_serverip[INET_ADDRSTRLEN];
module_param(DEFAULT_PORT, int, 0644);
module_param_string(socket_sip, socket_serverip, INET_ADDRSTRLEN, 0644);
//우선 지금은 간단한 socket 통신을 위한 API를 만든다.
//LEAP를 SMARTNIC안에 넣게 되면, IS_rdma_write와 같은 함수를 만드는 것이 필요하다
int ksocket_recv(struct socket *sock, struct sockaddr_in *addr, struct prefetch_request *request);
int ksocket_send(struct socket *sock, struct sockaddr_in *addr, unsigned type, pgoff_t pageid, struct page *page);

static void ksocket_start(void)
{
	int err, size;
	struct prefetch_request *request;
	size_t buflen;
	u8* addr;
	mutex_init(&my_mutex);

	mutex_lock(&my_mutex);
	current->flags |= PF_NOFREEZE;
	allow_signal(SIGKILL);
	kthread->running = 0;
	mutex_unlock(&my_mutex);

	/* create socket */
	/* TCP Socket -> ops */
	if(((err = sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &kthread->sock)) < 0)) {
		printk(KERN_INFO MODULE_NAME":Could not create SOCK_STREAM socket, error = %d\n", -ENXIO);
		goto out;
	}

	memset(&kthread->addr, 0, sizeof(struct sockaddr));
	kthread->addr.sin_family = AF_INET;
#ifdef HOST
	kthread->addr.sin_addr.s_addr = htonl(INADDR_ANY);
#else
	buflen = strlen(socket_serverip);
	if(buflen > INET_ADDRSTRLEN) {
		printk(KERN_ERR "buflen > INET_ADDRSTRLEN\n");
		return;
	}
	addr = (u8 *)&kthread->addr.sin_addr.s_addr;
	if(in4_pton(socket_serverip, buflen, addr, '\0', NULL) == 0) {
		printk(KERN_ERR "in4_pton in ksocket_start() failed\n");
		return;
	}
#endif
	kthread->addr.sin_port = htons(DEFAULT_PORT);

#ifdef HOST
	// If we are Host, We send a request to SmartNIC using frontswap_ops
	if(((err = kthread->sock->ops->bind(kthread->sock, (struct sockaddr*)&kthread->addr, sizeof(struct sockaddr))) < 0)) {
		printk(KERN_INFO MODULE_NAME": Could not bind or connect to socket, error = %d\n", -err);
		goto close_and_out;
	}
	printk(KERN_INFO MODULE_NAME":listening port %d\n", DEFAULT_PORT);
	
	if(((err = kthread->sock->ops->listen(kthread->sock, 0)) < 0)) {
		printk(KERN_INFO MODULE_NAME": Could not listen\n");
		goto close_and_out;
	}
	// Here Blocking 
	if(((err = kthread->sock->ops->accept(kthread->sock, &(kthread->client), 0)) < 0)) {
		printk(KERN_INFO MODULE_NAME": Could not accept\n");
		goto close_and_out;
	}
#else
	if(((err = kthread->sock->ops->connect(kthread->sock, (struct sockaddr*)&kthread->addr, sizeof(struct sockaddr), 0)) < 0)) {
		printk(KERN_INFO MODULE_NAME": Connect failed\n");
		goto close_and_out;
	}

	request = (struct prefetch_request *)kmalloc(sizeof(struct prefetch_request), GFP_KERNEL);
	
	// If we are SmartNIC, We waiting a request from HOST
	while(true) {
		memset(&request, 0, sizeof(request));
		printk("recv start\n");
		size = ksocket_recv(kthread->sock, &kthread->addr, request);
		printk("recv end\n");
		if(signal_pending(current)) break;
		if(size < 0) 
			printk(KERN_INFO MODULE_NAME":error getting stream, sock_recvmsg error = %d\n", size);
		else {
			printk(KERN_INFO MODULE_NAME":received %d bytes\n", size);
			/*	Here Data Processing Unit needed */
			/*  1 means rdma read, 2 means rdma write, 3 means send prefetch data */
			if(request->type == 1) {
				err = sswap_rdma_read_sync(request->page_address, (request->pageid << PAGE_SHIFT));
				if(err < 0) printk(KERN_WARNING MODULE_NAME": error sswap_rdma_read_sync\n");
			}
			else if(request->type == 2) {
				err = sswap_rdma_write(request->page_address, (request->pageid << PAGE_SHIFT));
				if(err < 0) printk(KERN_WARNING MODULE_NAME": error sswap_rdma_write\n");
			}
			else if(request->type == 3) {
				atomic_set(&send_metadata, request->page_address);
			}
		}
	}
#endif

close_and_out:
	sock_release(kthread->sock);
	kthread->sock = NULL;
out:
	kthread->thread = NULL;
	kthread->running = 0;
}

int ksocket_send(struct socket *sock, struct sockaddr_in *addr, unsigned type, pgoff_t pageid, struct page *page) 
{
	struct prefetch_request request;
	struct msghdr msg;
	struct iovec iov;
	mm_segment_t oldfs;
	int size = 0;

	request.type = type;
	request.pageid = pageid;
	request.page_address = (uint64_t)page_address(page);

	if(sock->sk == NULL) return 0;
	// Contain Request
	iov.iov_base = (void *)&request;
	iov.iov_len = sizeof(struct prefetch_request);

	msg.msg_flags = 0; // can
	msg.msg_name = addr; // can
	msg.msg_namelen = sizeof(struct sockaddr_in); // can
	msg.msg_control = NULL; // can
	msg.msg_controllen = 0; // can
	msg.msg_iter.count = 1;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
#else
	iov_iter_init(&msg.msg_iter, READ, &iov, 1, 1);
#endif

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	size = sock_sendmsg(sock, &msg);
	set_fs(oldfs);
	
	return size;
}

int ksocket_recv(struct socket *sock, struct sockaddr_in *addr, struct prefetch_request *request)
{
	struct msghdr msg;
	struct iovec iov;
	mm_segment_t oldfs;
	int size = 0;

	if(sock->sk == NULL) return 0;
	// Contain Request
	iov.iov_base = (void *)request;
	iov.iov_len = sizeof(struct prefetch_request);

	msg.msg_flags = 0;
	msg.msg_name = addr;
	msg.msg_namelen = sizeof(struct sockaddr_in);
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
#else
	iov_iter_init(&msg.msg_iter, READ, &iov, 1, 1);
#endif

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	size = sock_recvmsg(sock, &msg, msg.msg_flags);
	set_fs(oldfs);

	return size;
}

static int mmap_device_init(void)
{
	int alloc_ret = 0, cdev_err = 0;
	dev_t dev;

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

	mmapdev_class = class_create(THIS_MODULE, "mmap_device");
	if (IS_ERR(mmapdev_class)) {
		printk(KERN_ERR "class_create failed\n");
		goto OUT;
	}

	device_create(mmapdev_class, NULL, MKDEV(mmapdev_major, MINOR_BASE), NULL, DEV_NAME);
	data = vmalloc(DATA_SIZE);
	if (data == NULL) {
		printk(KERN_ERR "vmalloc failed\n");
		goto OUT;
	}
	memset(data, 0, DATA_SIZE);
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
	device_destroy(mmapdev_class, dev);
	class_destroy(mmapdev_class);
	cdev_del(mmapdev_cdev);
	unregister_chrdev_region(dev, MINOR_NUM);
	if(data) vfree(data);
	return 0;
}

int ksocket_init(void)
{
	int i;
	printk(KERN_ALERT "init mmap_device\n");
	/*
	if(mmap_device_init() == -1) {
		printk(KERN_WARNING "mmap_device_init() failed\n");
		return -ENOMEM;
	}
	*/
	printk(KERN_INFO "init kmalloc for transfer data between kernel and user\n");
	for(i = 0 ; i < PAGE_CNT ; i++) rdma_buf[i].page = alloc_page(GFP_KERNEL);
	atomic_set(&buf_info.head, 0);
	atomic_set(&buf_info.tail, 0);
	atomic_set(&buf_info.head_round, 0);
	atomic_set(&buf_info.tail_round, 0);
	buf_info.size = PAGE_CNT;
	
	printk(KERN_INFO "init socket thread\n");
	kthread = kmalloc(sizeof(struct kthread_t), GFP_KERNEL);
	memset(kthread, 0, sizeof(struct kthread_t));
	
	printk(KERN_INFO "init rdma thread\n");
	rdma_kthread = kmalloc(sizeof(struct kthread_t), GFP_KERNEL);
	memset(rdma_kthread, 0, sizeof(struct kthread_t));

	#ifdef HOST
	// Here just to call ksocket_start()
	printk(KERN_INFO "init_frontswap ops\n");
	frontswap_register_ops(&sswap_frontswap_ops);
	printk(KERN_INFO "init socket\n");
	ksocket_start();
	#else
	/*
	printk(KERN_INFO "init for rdma request\n");
	rdma_kthread->thread = kthread_run((void *)rdma_init, NULL, MODULE_NAME);
	if(IS_ERR(rdma_kthread->thread)) {
		printk(KERN_ERR MODULE_NAME":unable to start rdma init\n");
		kfree(rdma_kthread);
		rdma_kthread = NULL;
		return -ENOMEM;
	}
	
	if(rdma_init() < 0) {
		printk(KERN_WARNING "rdma init failed\n");
		return -ENOMEM;
	}
	*/
	// Here make thread to run recv_sockmsg()
	kthread->thread = kthread_run((void *)ksocket_start, NULL, MODULE_NAME);
	if(IS_ERR(kthread->thread)) {
		printk(KERN_INFO MODULE_NAME":unable to start kernel thread\n");
		kfree(kthread);
		kthread = NULL;
		return -ENOMEM;
	}
	
	#endif
	return 0;
}

void ksocket_exit(void)
{
	
	#if 0
		if(kthread->thread == NULL)
			printk(KERN_INFO MODULE_NAME": no kernel thread to kill\n");
		else {
			lock_kernel();
			err = kill_proc(kthread->thread->pid, SIGKILL, 1);
			unlock_kernel();

			if(err < 0) 
				printk(KERN_INFO MODULE_NAME": unknown error %d while trying to terminate kernel thread\n", -err);
			else {
				while(kthread->running == 1) 
					msleep(10);
				printk(KERN_INFO MODULE_NAME":successfully killed kernel thread!\n");
			}
		}
	#endif
		printk(KERN_WARNING "try mmap_device_exit\n");
		//mmap_device_exit();
		printk(KERN_WARNING "success mmap_device_exit\n");
		if(rdma_kthread && rdma_kthread->thread) {
			printk(KERN_INFO "stop rdma_kthread->thread\n");
			kthread_stop(rdma_kthread->thread);
		}
		if(kthread && kthread->running) {
			printk(KERN_INFO "stop kthread->thread\n");
			kthread_stop(kthread->thread);
		}
		if(kthread && kthread->sock != NULL) {
			sock_release(kthread->sock);
			kthread->sock = NULL;
		}
		if(rdma_kthread) kfree(rdma_kthread);
		if(kthread) kfree(kthread);
		kthread = NULL;
		rdma_kthread = NULL;
		
		printk(KERN_INFO MODULE_NAME":module unloaded\n");
}

static inline long myclock(void)
{
	return ktime_get_ns();
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
	/* need to send write request */
	int retval = ksocket_send(kthread->sock, &kthread->addr, type, pageid, page);
	if(retval >= sizeof(struct prefetch_request)) return 0;
	else return -1;
}

static int sswap_load(unsigned type, pgoff_t pageid, struct page *page)
{
	/* First, Find a Page in hash table */
	bool find = false;
	struct prefetch_data *pdata;
	uint64_t addr = (uint64_t)page_address(page);
	int err, retval;

	hash_for_each_possible(h_prefetch_data, pdata, my_hash_list, addr) {
		memcpy(page_address(page), pdata->buf, PAGE_SIZE);
		find = true;
		break;
	}
	if(find) return 0;
	hash_for_each_possible(h_metadata_prefetch_data, pdata, my_hash_list, addr) {
		/* need to request for prefetch data in SmartNIC */
		ksocket_send(kthread->sock, &kthread->addr, 3, pageid, page);
		find = true;
		break;
	}
	if(find) {
		retval = poll_data(page);
		err = 0;
		if(!retval) 
			//직접 read 요청을 보내는 코드가 필요
			err = host_rdma_read_sync(page, (pageid << PAGE_SHIFT));
		if(err < 0) 
			printk(KERN_WARNING "sswap_rdma_read_sync failed\n");
		return err;
	}
	/* send a read request */
	retval = ksocket_send(kthread->sock, &kthread->addr, type, pageid, page);
	if(retval >= sizeof(struct prefetch_request)) return 0;
	else return -1;
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
	.invalidate_page = sswap_invalidate_page,
	.invalidate_area = sswap_invalidate_area,
};

module_init(ksocket_init);
module_exit(ksocket_exit);

MODULE_DESCRIPTION("SmartNIC Tracker");
MODULE_LICENSE("GPL");













