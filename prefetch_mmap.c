#include "prefetch_mmap.h"
#include "prefetch_rdma.h"

extern DECLARE_HASHTABLE(h_prefetch_data, 6);
extern DECLARE_HASHTABLE(h_metadata_prefetch_data, 6);
extern DECLARE_HASHTABLE(h_write_prefetch_data, 6);
extern struct rdma_buf rdma_buf[PAGE_CNT];
extern struct buf_info buf_info;
extern struct rdma_buf write_rdma_buf[PAGE_CNT];
extern struct buf_info write_buf_info;

int *data = NULL;
atomic_t counter = ATOMIC_INIT(0);
atomic_t send_metadata = ATOMIC_INIT(0);

atomic_t h_prefetch_data_keys_idx = ATOMIC_INIT(0);
atomic_t h_metadata_prefetch_data_keys_idx = ATOMIC_INIT(0);
atomic_t h_write_prefetch_data_keys_idx = ATOMIC_INIT(0);

uint64_t h_prefetch_data_keys[PAGE_CNT];
uint64_t h_metadata_prefetch_data_keys[PAGE_CNT];
uint64_t h_write_prefetch_data_keys[PAGE_CNT];

typedef enum HASHTABLE_TYPE {
	H_PREFETCH_DATA,
	H_METADATA_PREFETCH_DATA,
	H_WRITE_PREFETCH_DATA
} HASHTABLE_TYPE;

static bool can_insert(uint64_t addr, uint64_t ts)
{
	struct prefetch_data *pdata;
	bool can = true;

	hash_for_each_possible(h_write_prefetch_data, pdata, my_hash_list, addr) {
		if (pdata->ts > ts) can = false;
		else hash_del(&pdata->my_hash_list);
		break;
	}

	return can;
}

static void prefetch_lru_drain(uint64_t addr, HASHTABLE_TYPE type)
{
	struct prefetch_data *pdata;
	int idx;

	pr_info("start: %s\n", __FUNCTION__);

	if(type == H_PREFETCH_DATA) {
		idx = atomic_read(&h_prefetch_data_keys_idx);
		if(h_prefetch_data_keys[idx]) {
			hash_for_each_possible(h_prefetch_data, pdata, my_hash_list, h_prefetch_data_keys[idx]) {
				hash_del(&pdata->my_hash_list);
			}
		}
		h_prefetch_data_keys[idx] = addr;
		atomic_set(&h_prefetch_data_keys_idx, (idx + 1) % PAGE_CNT);
	}
	else if(type == H_METADATA_PREFETCH_DATA) {
		idx = atomic_read(&h_metadata_prefetch_data_keys_idx);
		if(h_metadata_prefetch_data_keys[idx]) {	
			hash_for_each_possible(h_metadata_prefetch_data, pdata, my_hash_list, h_metadata_prefetch_data_keys[idx]) {
				hash_del(&pdata->my_hash_list);
			}
		}
		h_metadata_prefetch_data_keys[idx] = addr;
		atomic_set(&h_metadata_prefetch_data_keys_idx, (idx + 1) % PAGE_CNT);
	}
	else if(type == H_WRITE_PREFETCH_DATA) {
		idx = atomic_read(&h_write_prefetch_data_keys_idx);
		if(h_write_prefetch_data_keys[idx]) {
			hash_for_each_possible(h_write_prefetch_data, pdata, my_hash_list, h_write_prefetch_data_keys[idx]) {
				hash_del(&pdata->my_hash_list);
			}
		}
		h_write_prefetch_data_keys[idx] = addr;
		atomic_set(&h_write_prefetch_data_keys_idx, (idx + 1) % PAGE_CNT);
	}

	pr_info("end: %s\n", __FUNCTION__);
}

void prefetch_lru_drain_wrapper(uint64_t addr, uint8_t type)
{
	if (type == 0) prefetch_lru_drain(addr, H_PREFETCH_DATA);
	else if (type == 1) prefetch_lru_drain(addr, H_METADATA_PREFETCH_DATA);
	else if (type == 2) prefetch_lru_drain(addr, H_WRITE_PREFETCH_DATA);
}

static void mmap_vma_open(struct vm_area_struct *vma)
{
	atomic_inc(&counter);
	printk("%s: %d\n", __func__, atomic_read(&counter));

	printk("vm_pgoff: %08lx\n", vma->vm_pgoff);
	printk("vm_start: %08lx\n", vma->vm_start);
	printk("vm_end  : %08lx\n", vma->vm_end);
}

static void mmap_vma_close(struct vm_area_struct *vma)
{
	atomic_dec(&counter);
	printk("%s: %d\n", __func__, atomic_read(&counter));
}
/*
	fault operation은 page fault가 일어났을 때 호출되는 operation으로,
	해당 handler에서 가상 메모리를 페이지로 매핑하는 핵심 작업을 수행
*/
static int mmap_vm_fault(struct vm_fault *vmf)
{
	struct page *page = NULL;
	unsigned long offset = 0;
	void *page_ptr = NULL;

	printk("%s\n", __func__);
	if (vmf == NULL)
		return VM_FAULT_SIGBUS;

	offset = vmf->address - vmf->vma->vm_start;
	if (offset >= DATA_SIZE)
		return VM_FAULT_SIGBUS;

	page_ptr = data + offset;
	/* 메모리를 page로 변환 */
	page = vmalloc_to_page(page_ptr);
	/* 해당 page를 가져온다 */
	get_page(page);
	vmf->page = page;
	return 0;
}

struct vm_operations_struct vma_ops = {
	.open = mmap_vma_open,
	.close = mmap_vma_close,
	.fault = mmap_vm_fault
};

static int mmap_open(struct inode *inode, struct file *filp)
{
	return 0;
}

static int mmap_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static int mmap_remap(struct file *filp, struct vm_area_struct *vma)
{
	printk("%s\n", __func__);

	vma->vm_flags |= VM_IO;
	vma->vm_ops = &vma_ops;
	mmap_vma_open(vma);
	return 0;
}
static ssize_t mmap_read_host(struct file *filp, char __user *buf,
		size_t count, loff_t *offset)
{
	uint64_t addr, ts;
	char *kbuf = NULL;

	pr_info("start: %s\n", __FUNCTION__);
	kbuf = (char *)kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (kbuf == NULL) {
		pr_err("in mmap_read() kmalloc failed\n");
		return -1;
	}
	if (atomic_read(&write_buf_info.head_round) == atomic_read(&write_buf_info.tail_round))
		if (atomic_read(&write_buf_info.head) >= atomic_read(&write_buf_info.tail)) {
			pr_info("in mmap_read(), here are no data\n");
			return 0;
		}

	addr = write_rdma_buf[atomic_read(&write_buf_info.head)].host_page;
	ts = write_rdma_buf[atomic_read(&write_buf_info.head)].ts;
	memcpy(kbuf, (char *)page_address(write_rdma_buf[atomic_read(&write_buf_info.head)].page), PAGE_SIZE);

	if (copy_to_user(buf, &addr, sizeof(addr)) > 0) {
		goto fail_copy_to_user;
	}
	if (copy_to_user(buf + sizeof(addr), &ts, sizeof(ts)) > 0) 
		goto fail_copy_to_user;
	if (copy_to_user(buf + sizeof(addr) + sizeof(ts), kbuf, count - sizeof(addr) - sizeof(ts)) > 0)
		goto fail_copy_to_user;

	kfree(kbuf);
	atomic_head_inc_write();
	pr_info("end: %s\n", __FUNCTION__);
	return count;

fail_copy_to_user:
	pr_err("copy_to_user failed\n");
	kfree(kbuf);
	return -1;
}
/* fastswap code에 맞춰진 mmap_read, mmap_write */
/* Kernel to Host */
static ssize_t mmap_read_smartnic(struct file *filp, char __user *buf,
		size_t count, loff_t *offset)
{
	uint64_t addr, ts;
    char *kbuf = NULL;
    pr_info("start: %s\n", __FUNCTION__);

    kbuf = (char *)kmalloc(PAGE_SIZE, GFP_KERNEL);
    if(kbuf == NULL) {
        printk(KERN_ERR "in mmap_read() kmalloc failed\n");
        return -1;
    }

    if(atomic_read(&send_metadata) != 0) {
        addr = atomic_read(&send_metadata);
        memset(kbuf, '\0', PAGE_SIZE);
        if(copy_to_user(buf, &addr, sizeof(addr)) > 0)
            goto fail_copy_to_user;
        if(copy_to_user(buf + sizeof(addr), kbuf, count - sizeof(addr)) > 0)
            goto fail_copy_to_user;

        atomic_set(&send_metadata, 0);
        kfree(kbuf);
        return count;
    }

    if(atomic_read(&buf_info.head_round) == atomic_read(&buf_info.tail_round))
        if(atomic_read(&buf_info.head) >= atomic_read(&buf_info.tail)) {
            pr_info("in mmap_read(), here are no data\n");
            return 0;
        }

    addr = rdma_buf[atomic_read(&buf_info.head)].host_page;
	ts = rdma_buf[atomic_read(&buf_info.head)].ts;
    /* 쓰여진 가상메모리 주소에서 쓰는 건가? */
    memcpy(kbuf, (char *)page_address(rdma_buf[atomic_read(&buf_info.head)].page), PAGE_SIZE);

    if(copy_to_user(buf, &addr, sizeof(addr)) > 0) {
        goto fail_copy_to_user;
	}
	if(copy_to_user(buf + sizeof(addr), &ts, sizeof(ts)) > 0)
		goto fail_copy_to_user;
    if(copy_to_user(buf + sizeof(addr) + sizeof(ts), kbuf, count - sizeof(addr) - sizeof(ts)) > 0)
        goto fail_copy_to_user;

    kfree(kbuf);
    atomic_head_inc();
    pr_info("end: %s\n", __FUNCTION__);
    return count;

fail_copy_to_user:
    printk(KERN_WARNING "copy_to_user failed\n");
    kfree(kbuf);
    return -1;
}
/* Host to Kernel */
static ssize_t mmap_write_host(struct file *filp, const char __user *buf,
		size_t count, loff_t *offset)
{
	/* Here need to code that insert data to cache */
    /* 해당 phys addr에 데이터를 넣어야 한다 */
    struct prefetch_data *pdata = NULL;
    pr_info("start: %s\n", __FUNCTION__);

    pdata = (struct prefetch_data *)kmalloc(sizeof(struct prefetch_data), GFP_KERNEL);
    if(pdata == NULL) {
        printk(KERN_ERR "in mmap_write() vmalloc failed()\n");
        return -1;
    }

    pdata->buf = (char *)kmalloc(PAGE_SIZE, GFP_KERNEL);
    if(pdata->buf == NULL) {
        printk(KERN_ERR "in mmap_write() vmalloc failed()\n");
        kfree(pdata);
        return -1;
    }

    pr_info("request count = %lu\n", count);
    if(copy_from_user(&(pdata->addr), buf, sizeof(pdata->addr)) > 0) {
        goto fail_copy_from_user;
	}
	if(copy_from_user(&(pdata->ts), buf + sizeof(pdata->addr), sizeof(pdata->ts)) > 0) {
		goto fail_copy_from_user;
	}
    if(copy_from_user(pdata->buf, buf + sizeof(pdata->addr) + sizeof(pdata->ts), count - sizeof(pdata->addr) - sizeof(pdata->ts)) > 0) {
        goto fail_copy_from_user;
	}

	// check this data is valid or invalid
	if (can_insert(pdata->addr, pdata->ts) == false) {
		pr_info("This data is invalid");
		return 0;
	}

    memset(&(pdata->my_hash_list), 0, sizeof(struct hlist_node));
    if(pdata->buf == NULL) {
        // hash_table, node, key
		kfree(pdata->buf); // This is metadata, so useless
		prefetch_lru_drain(pdata->addr, H_METADATA_PREFETCH_DATA);
        hash_add(h_metadata_prefetch_data, &(pdata->my_hash_list), pdata->addr);
    }
    else {
        // hash_table, node, key
		prefetch_lru_drain(pdata->addr, H_PREFETCH_DATA);
        hash_add(h_prefetch_data, &(pdata->my_hash_list), pdata->addr);
    }

    kfree(pdata->buf);
    kfree(pdata);
	return count;

fail_copy_from_user:
    printk(KERN_WARNING "copy_from_user() failed\n");
    kfree(pdata->buf);
    kfree(pdata);
    return -1;
}
/* SmartNIC for write */
static ssize_t mmap_write_smartnic(struct file *flip, const char __user *buf,
		size_t count, loff_t *offset)
{
	struct prefetch_data *pdata = NULL;
	pr_info("start: %s\n", __FUNCTION__);

	pdata = (struct prefetch_data *)kmalloc(sizeof(struct prefetch_data), GFP_KERNEL);
	if (pdata == NULL) {
		pr_info("kmalloc failed\n");
		return -1;
	}

	pdata->buf = (char *)kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (pdata->buf == NULL) {
		pr_info("kmalloc failed\n");
		kfree(pdata);
		return -1;
	}

    if(copy_from_user(&(pdata->addr), buf, sizeof(pdata->addr)) > 0) {
        goto fail_copy_from_user;
    }
    if(copy_from_user(&(pdata->ts), buf + sizeof(pdata->addr), sizeof(pdata->ts)) > 0) {
        goto fail_copy_from_user;
	}
    if(copy_from_user(pdata->buf, buf + sizeof(pdata->addr) + sizeof(pdata->ts), count - sizeof(pdata->addr) - sizeof(pdata->ts)) > 0) {
        goto fail_copy_from_user;
	}
	
	memset(&(pdata->my_hash_list), 0, sizeof(struct hlist_node));
	pr_info("insert to h_write_prefetch_data");
	
	prefetch_lru_drain(pdata->addr, H_WRITE_PREFETCH_DATA);
	hash_add(h_write_prefetch_data, &(pdata->my_hash_list), pdata->addr);

	kfree(pdata->buf);
	kfree(pdata);
	return count;

fail_copy_from_user:
	printk(KERN_WARNING "copy_from_user() failed\n");
	kfree(pdata->buf);
	kfree(pdata);
	return -1;
}

static loff_t mmap_lseek(struct file *filp, loff_t offset, int org)
{
	loff_t ret;
	//printk("%s\n", __func__);

	switch (org)
	{
		case SEEK_SET:
			filp->f_pos = offset;
			ret = filp->f_pos;
			force_successful_syscall_return();
			break;

		case SEEK_CUR:
			filp->f_pos += offset;
			ret = filp->f_pos;
			force_successful_syscall_return();
			break;

		default:
			ret = -EINVAL;
	}

	return ret;
}

struct file_operations mmap_fops = {
	.open = mmap_open,
	.release = mmap_release,
#ifdef HOST
	.read = mmap_read_host,
	.write = mmap_write_host,
#else
	.read = mmap_read_smartnic,
	.write = mmap_write_smartnic,
#endif
	.mmap = mmap_remap,
	.llseek = mmap_lseek
};

void before_write(struct page *page, uint64_t ts)
{
	struct prefetch_data *pdata;
	uint64_t addr;

	pr_info("start: %s\n", __FUNCTION__);
	addr = (uint64_t)page_address(page);

	hash_for_each_possible(h_prefetch_data,  pdata, my_hash_list, addr) {
		pr_info("addr data deleted\n");
		hash_del(&pdata->my_hash_list);
	}
	hash_for_each_possible(h_metadata_prefetch_data, pdata, my_hash_list, addr) {
		pr_info("addr metadata deleted\n");
		hash_del(&pdata->my_hash_list);
	}
	
	hash_for_each_possible(h_write_prefetch_data, pdata, my_hash_list, addr) {
		hash_del(&pdata->my_hash_list);
	}

	pdata = (struct prefetch_data *)kmalloc(sizeof(struct prefetch_data), GFP_KERNEL);
	if (pdata == NULL) {
		pr_info("kmalloc failed in before write()\n");
		return;
	}
	pdata->buf = (char *)kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (pdata->buf == NULL) {
		pr_info("kmalloc failed in before write(), buf\n");
		kfree(pdata);
		return;
	}

	pdata->addr = addr;
	pdata->ts = ts;
	memcpy(pdata->buf, page_address(page), PAGE_SIZE);
	prefetch_lru_drain(pdata->addr, H_WRITE_PREFETCH_DATA);
	hash_add(h_write_prefetch_data, &(pdata->my_hash_list), pdata->addr);
	
	pr_info("end: %s\n", __FUNCTION__);
}

MODULE_LICENSE("GPL");
