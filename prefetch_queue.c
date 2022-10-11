#include "ksocket.h"
#include "prefetch_queue.h"

extern struct prefetch_request_list *prefetch_request_list;
extern struct list_head *head;

void push_queue(struct prefetch_request *req)
{
	prefetch_request_list = (struct prefetch_request_list *) kmalloc(sizeof(struct prefetch_request_list), GFP_KERNEL);
	if (prefetch_request_list == NULL) {
		pr_err("%s : kmalloc failed\n", __FUNCTION__);
		return;
	}
	prefetch_request_list->req = (struct prefetch_request *) kmalloc(sizeof(struct prefetch_request), GFP_KERNEL);
	if (prefetch_request_list->req == NULL) {
		pr_err("%s : req kmalloc failed\n", __FUNCTION__);
		return;
	}

	prefetch_request_list->req->type = req->type;
	prefetch_request_list->req->pageid = req->pageid;
	prefetch_request_list->req->page_address = req->page_address;
	prefetch_request_list->req->ts = req->ts;

	list_add_tail(&prefetch_request_list->queue_list, head);
	return;
}

struct prefetch_request * pop_queue(void) 
{
	struct prefetch_request_list *node;
	if (list_empty(head))
		return NULL;
	
	node = list_first_entry(head, struct prefetch_request_list, queue_list);
	if (node == NULL)
		return NULL;

	return node->req;
}
