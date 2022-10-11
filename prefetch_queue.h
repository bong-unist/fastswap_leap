#ifndef __PREFETCH_QUEUE_H
#define __PREFETCH_QUEUE_H

#include <linux/list.h>
#include <linux/slab.h>

void push_queue(struct prefetch_request *req);
struct prefetch_request * pop_queue(void);

#endif
