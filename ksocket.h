#ifndef _ksocket_h_
#define _ksocket_h_

#include <linux/ip.h>
#include <linux/in.h>

struct prefetch_request {
	unsigned type;
	pgoff_t pageid;
	uint64_t page_address;
	uint64_t ts;
};

struct prefetch_request_list {
	struct list_head queue_list;
	struct prefetch_request *req;
};

struct socket;
struct sockaddr;
struct in_addr;
typedef struct socket * ksocket_t;

ksocket_t ksocket(int domain, int type, int protocol);
int kclose(ksocket_t socket);

int kbind(ksocket_t socket, struct sockaddr *address, int address_len);
int klisten(ksocket_t socket, int backlog);
int kconnect(ksocket_t socket, struct sockaddr *address, int address_len);
ksocket_t kaccept(ksocket_t socket, struct sockaddr *address, int *address_len);

int ksocket_send(ksocket_t sock, struct sockaddr_in *addr, unsigned type, pgoff_t pageid, struct page *page, uint64_t ts);
int ksocket_recv(ksocket_t sock, struct sockaddr_in *addr, struct prefetch_request *request);

char *inet_ntoa(struct in_addr *in);
#endif
