#include <linux/module.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/in.h>
#include <net/sock.h>
#include <asm/processor.h>
#include <asm/uaccess.h>
#include "ksocket.h"

MODULE_LICENSE("GPL");

ksocket_t ksocket(int domain, int type, int protocol)
{
	struct socket *sk = NULL;
	int ret = 0;

	ret = sock_create(domain, type, protocol, &sk);
	if(ret < 0) 
	{
		printk(KERN_INFO "sock_create failed\n");
		return NULL;
	}

	printk("sock_create sk = 0x%p\n", sk);
	return sk;
}

int kbind(ksocket_t socket, struct sockaddr *address, int address_len)
{
	struct socket *sk;
	int ret = 0;

	sk = (struct socket *)socket;
	ret = sk->ops->bind(sk, address, address_len);
	printk("kbind ret = %d\n", ret);

	return ret;
}

int klisten(ksocket_t socket, int backlog)
{
	struct socket *sk;
	int ret;

	sk = (struct socket *)socket;
	if ((unsigned)backlog > SOMAXCONN)
		backlog = SOMAXCONN;

	ret = sk->ops->listen(sk, backlog);
	return ret;
}

int kconnect(ksocket_t socket, struct sockaddr *address, int address_len)
{
	struct socket *sk;
	int ret;

	sk = (struct socket *)socket;
	ret = sk->ops->connect(sk, address, address_len, 0);

	return ret;
}

ksocket_t kaccept(ksocket_t socket, struct sockaddr *address, int *address_len)
{
	struct socket *sk;
	struct socket *new_sk = NULL;
	int ret;

	sk = (struct socket *)socket;
	printk("family = %d, type = %d, protocol = %d\n", 
			sk->sk->sk_family, sk->type, sk->sk->sk_protocol);

	ret = sock_create(sk->sk->sk_family, sk->type, sk->sk->sk_protocol, &new_sk);
	if (ret < 0)
		return NULL;
	if (!new_sk)
		return NULL;

	new_sk->type = sk->type;
	new_sk->ops = sk->ops;

	ret = sk->ops->accept(sk, new_sk, 0, true);
	if (ret < 0)
		goto error_kaccept;

	return new_sk;

error_kaccept:
	sock_release(new_sk);
	return NULL;
}

int ksocket_send(ksocket_t sock, struct sockaddr_in *addr, unsigned type, pgoff_t pageid, struct page *page, uint64_t ts)
{
    struct prefetch_request request;
    struct msghdr msg;
    struct iovec iov;
    mm_segment_t oldfs;
	unsigned nr_segments = 1;
    int size = 0;

    request.type = type;
    request.pageid = pageid;
    request.page_address = (uint64_t)page_address(page);
	request.ts = ts;

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
    iov_iter_init(&(msg.msg_iter), READ, &iov, nr_segments, iov.iov_len);
#endif

    oldfs = get_fs();
    set_fs(KERNEL_DS);
    size = sock_sendmsg(sock, &msg);
    set_fs(oldfs);
    
	printk("sock_sendmsg = %d\n", size);
    return size;
}

int ksocket_recv(ksocket_t sock, struct sockaddr_in *addr, struct prefetch_request *request)
{
    struct msghdr msg;
    struct iovec iov;
    mm_segment_t oldfs;
	unsigned nr_segments = 1;
    int size = 0;

    if(sock->sk == NULL) return 0;
    // Contain Request
    iov.iov_base = (void *)request;
    iov.iov_len = sizeof(struct prefetch_request);

    msg.msg_flags = MSG_DONTWAIT;
    msg.msg_name = addr;
    msg.msg_namelen = sizeof(struct sockaddr_in);
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
#else
    iov_iter_init(&msg.msg_iter, WRITE, &iov, nr_segments, iov.iov_len);
#endif

    oldfs = get_fs();
    set_fs(KERNEL_DS);
	    size = sock_recvmsg(sock, &msg, msg.msg_flags);
    set_fs(oldfs);

    return size;
}

char *inet_ntoa(struct in_addr *in)
{
	char* str_ip = NULL;
	u_int32_t int_ip = 0;
	
	str_ip = kmalloc(16 * sizeof(char), GFP_KERNEL);
	if (!str_ip)
		return NULL;
	else
		memset(str_ip, 0, 16);

	int_ip = in->s_addr;
	
	sprintf(str_ip, "%d.%d.%d.%d",  (int_ip      ) & 0xFF,
									(int_ip >> 8 ) & 0xFF,
									(int_ip >> 16) & 0xFF,
									(int_ip >> 24) & 0xFF);
	return str_ip;
}




