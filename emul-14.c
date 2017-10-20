#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>

#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/errno.h>
#include <linux/types.h>

#include <linux/blkdev.h>
#include <linux/hdreg.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/lightnvm.h>
#include <linux/blk-mq.h>
#include <linux/hrtimer.h>
#include <linux/vmalloc.h>

#define rqd_is_write(rqd) (rqd->opcode & 1)

static int bs = 4096;

static int gb = 10;

static int hw_queue_depth = 64;

static int submit_queues = 8;						// default: number of cores
module_param(submit_queues, int, S_IRUGO);
MODULE_PARM_DESC(submit_queues, "number of submit queues");

static unsigned int nr_rwb = 8;
module_param(nr_rwb, int, S_IRUGO);
MODULE_PARM_DESC(nr_rwb, "Number of RWB");

static int wt_pin = 1;							// 0 unpin,  1 pin
module_param(wt_pin, int, S_IRUGO);
MODULE_PARM_DESC(wt_pin, "pblk-writer pinning");

static int user_rb_option = 1;						// 1 rand,  2 max (remain)
module_param(user_rb_option, int, S_IRUGO);
MODULE_PARM_DESC(user_rb_option, "ring buffer choice");

static int gc_rb_option = 1;						// 1 rand,  2 max (remain)
module_param(gc_rb_option, int, S_IRUGO);
MODULE_PARM_DESC(gc_rb_option, "ring buffer choice of GC");

static int wt_nice = 1;							// 0 low,  1 high
module_param(wt_nice, int, S_IRUGO);
MODULE_PARM_DESC(wt_nice, "pblk-writer nice value");

static int gc = 0;

static int nr_devices = 1;
static int num_lun, num_blk;
static u64 ***lba_list;
static int home_node = NUMA_NO_NODE;
static int emuld_indexes;
static int major;
static struct mutex lock;
static struct kmem_cache *ppa_cache;

static LIST_HEAD(emuld_list);

enum {
	EMUL_IRQ_NONE		= 0,
	EMUL_IRQ_SOFTIRQ	= 1,
	EMUL_IRQ_TIMER		= 2,
};

enum {
	EMUL_Q_BIO	= 0,
	EMUL_Q_RQ	= 1,
	EMUL_Q_MQ	= 2,
};

struct page_list {
	struct page_node *head;
	spinlock_t lock;
};

struct page_node {
	struct page *page;
	struct page_node *next;
};

struct page_list page_pool;

static int irqmode = EMUL_IRQ_SOFTIRQ;

struct emuld_cmd {
	struct list_head list;
	struct llist_node ll_list;
	struct call_single_data csd;
	struct request *rq;
	struct bio *bio;
	unsigned int tag;
	struct emuld_queue *eq;
	struct hrtimer timer;
};

struct emuld_queue {
	unsigned long *tag_map; //?
	wait_queue_head_t wait;
	unsigned int queue_depth;

	struct emuld_cmd *cmds;
};

struct emuld {
	struct list_head list;
	unsigned int index;
	struct request_queue *q;
	struct gendisk *disk;
	struct nvm_dev *ndev;
	struct blk_mq_tag_set tag_set;		// MQ
	struct hrtimer timer;
	unsigned int queue_depth;
	spinlock_t lock;

	struct emuld_queue *queues;
	unsigned int nr_queues;
	char disk_name[DISK_NAME_LEN];

	struct radix_tree_root emul_pages;
};


static struct page *emul_lookup_page(struct emuld *emuld, u64 idx)
{
	struct page *page;

	rcu_read_lock();
	page = radix_tree_lookup(&emuld->emul_pages, (pgoff_t) idx);
	rcu_read_unlock();

	return page;
}

static struct page *get_page_from_pool(void)
{
	struct page *page;
	struct page_node *temp;


	temp = page_pool.head;
	if( !temp )
		return NULL;
	
	page = temp->page;

	page_pool.head = temp->next;

	vfree(temp);

	return page;
}

static struct page *emul_insert_page(struct emuld *emuld, u64 idx)
{
	struct page *page;
	gfp_t gfp_flags;

	page = emul_lookup_page(emuld, idx);
	if( page ) {
		printk("JJY: same index exist\n");
		return page;
	}

	spin_lock(&page_pool.lock);
	page = get_page_from_pool();
	spin_unlock(&page_pool.lock);

	if( !page )  {
		gfp_flags = GFP_NOIO | __GFP_ZERO;

		page = alloc_page(gfp_flags);
		if( !page )
			return NULL;
	}

	if( radix_tree_preload(GFP_NOIO) )
	{
		__free_page(page);
		return NULL;
	}

	page->index = idx;

	spin_lock(&emuld->lock);
	if( radix_tree_insert(&emuld->emul_pages, idx, page) )
	{
		__free_page(page);
		page = radix_tree_lookup(&emuld->emul_pages, idx);
	}

	spin_unlock(&emuld->lock);

	radix_tree_preload_end();

	return page;
}

static void emul_free_page(struct emuld *emuld, u64 idx)
{
	struct page *page;

	spin_lock(&emuld->lock);
	page = radix_tree_delete(&emuld->emul_pages, (pgoff_t) idx);
	spin_unlock(&emuld->lock);

	if( page )
		__free_page(page);
}

static void emul_free_pages(struct emuld *emuld)
{
	unsigned long pos = 0;
	struct page *pages[16];
	int nr_pages;

	spin_lock(&emuld->lock);
	do {
		int i;

		nr_pages = radix_tree_gang_lookup(&emuld->emul_pages, (void **)pages, pos, 16);

		for( i = 0 ; i < nr_pages ; i++ )
		{
			void *ret;

			pos = pages[i]->index;
			ret = radix_tree_delete(&emuld->emul_pages, pos);
			__free_page(pages[i]);
		}

		pos++;
	} while( nr_pages == 16 );

	spin_unlock(&emuld->lock);
}

static void copy_from_emul(void *dst, u64 ppa)
{
	struct page *page;
	void *src;
	struct emuld *emuld;

	emuld = list_entry(emuld_list.next, struct emuld, list);
	page = emul_lookup_page(emuld, ppa);

	if( page )
	{
		src = kmap_atomic(page);
		memcpy(dst, src, 4096); // ?
		kunmap_atomic(src);
	}
	else
	{
		printk("JJY: nodata\n");
		memset(dst, 0, 4096);	// ?
	}
}

static void copy_to_emul(void *src, u64 ppa)
{
	struct page *page;
	void *dst;
	struct emuld *emuld;

	emuld = list_entry(emuld_list.next, struct emuld, list);
	page = emul_insert_page(emuld, ppa);

//	if( !page )
//		return -ENOSPC;

	dst = kmap_atomic(page);
	memcpy(dst, src, 4096);
	kunmap_atomic(dst);
}

static void emul_handle_request(struct nvm_rq *rqd, u64 ppa, struct page *page, unsigned int offset, unsigned int len) 
{
	void *rq_page;

	rq_page = kmap_atomic(page);

	if( rqd->opcode == NVM_OP_PREAD )
	{
//		pr_info("OCSSD emulator: READ\n");
		copy_from_emul(rq_page, ppa);
	}
	else if( rqd->opcode == NVM_OP_PWRITE )
	{
//		pr_info("OCSSD emulator: WRITE\n");
		copy_to_emul(rq_page, ppa);
	}

	kunmap_atomic(rq_page);

}

static void emul_insert_page_to_pool(struct page *page)
{
	struct page_node *new;

	new = (struct page_node *) vmalloc(sizeof(struct page_node));

	new->page = page;

	spin_lock(&page_pool.lock);
	new->next = page_pool.head;
	page_pool.head = new;
	spin_unlock(&page_pool.lock);
}


static void emul_handle_erase(struct request *rq, struct nvm_rq *rqd)
{
	unsigned long pos = 0;
	struct page *pages[16];
	int nr_pages;
	struct emuld *emuld;
	struct ppa_addr temp;

	emuld = list_entry(emuld_list.next, struct emuld, list);

	do {
		int i;

		nr_pages = radix_tree_gang_lookup(&emuld->emul_pages, (void **)pages, pos, 16);

		for( i = 0 ; i < nr_pages ; i++ )
		{
			void *ret;

			temp.ppa = pos = pages[i]->index;			

			if( (temp.g.blk == rqd->ppa_addr.g.blk) && (temp.g.lun == rqd->ppa_addr.g.lun) )
			{
				ret = radix_tree_delete(&emuld->emul_pages, pos);

				emul_insert_page_to_pool(pages[i]);
			}
		}

		pos++;
	} while( nr_pages == 16 );
}

static blk_status_t emul_queue_rq(struct blk_mq_hw_ctx *hctx,
			const struct blk_mq_queue_data *bd)
{
	struct request *rq = bd->rq;
	struct emuld_cmd *cmd = blk_mq_rq_to_pdu(rq);
	struct nvm_rq *rqd;
	struct bio *pbio;
	struct bio_vec bvec;
	struct bvec_iter iter;
	int i = 0;
	
	cmd->rq = rq;
	cmd->eq = hctx->driver_data;

	blk_mq_start_request(rq);

	rqd = rq->end_io_data;
	// request handling
	if( rq->bio->bi_iter.bi_sector == 0 )
		goto complete;
complete:	
	blk_mq_complete_request(rq);

	return 0;
}

static void emul_init_queue(struct emuld *emuld, struct emuld_queue *eq)
{
	init_waitqueue_head(&eq->wait);
	eq->queue_depth = emuld->queue_depth;
}

static int emul_init_hctx(struct blk_mq_hw_ctx *hctx, void *data, unsigned int index)
{
	struct emuld *emuld = data;
	struct emuld_queue *eq = &emuld->queues[index];

	hctx->driver_data = eq;
	emul_init_queue(emuld, eq);
	emuld->nr_queues++;             // ??

	return 0;
}

static void put_tag(struct emuld_queue *eq, unsigned int tag)
{
	clear_bit_unlock(tag, eq->tag_map);

	if(waitqueue_active(&eq->wait))
		wake_up(&eq->wait);
}

static void free_cmd(struct emuld_cmd *cmd)
{
	put_tag(cmd->eq, cmd->tag);
}

static void end_cmd(struct emuld_cmd *cmd)
{
	if( !(cmd->rq) )
		pr_err("cmd rq is null\n");

	blk_mq_end_request(cmd->rq, 0);

//	free_cmd(cmd);
}

static void emul_softirq_done_fn(struct request *rq)
{
	end_cmd(blk_mq_rq_to_pdu(rq));
}

static struct blk_mq_ops emul_mq_ops = {
	.queue_rq	= emul_queue_rq,
	.init_hctx	= emul_init_hctx,
	.complete	= emul_softirq_done_fn,
};

static int emul_id(struct nvm_dev *dev, struct nvm_id *id){
	struct nvm_id_group *grp;
	
	id->nr_rwb = nr_rwb;
	id->user_rb_option = user_rb_option;
	id->gc_rb_option = gc_rb_option;
	id->wt_pin = wt_pin;
	id->wt_nice = wt_nice;
	
	id->ver_id = 0x1;
	id->vmnt = 0;
	id->cap = cpu_to_le32(0x3);
	id->dom = 0;

	grp = &id->grp;
	grp->mtype = 0;
	grp->fmtype = 0;

	grp->num_ch = 1;			/*number of channel, dev->nr_chnl*/
	grp->num_pg = 512;			/*number of pages per block*/
	num_lun = grp->num_lun = 4;		/*luns per chnl, dev->luns_per_chnl*/
	num_blk = grp->num_blk = 256;			/*number of blocks per lun, dev->blks_per_luns*/
	grp->num_pln = 4;			/*number of planes, dev->nr_planes*/

	/*physical page address format*/
	id->ppaf.sect_offset = 0;
        id->ppaf.sect_len = fls(cpu_to_le16(1) - 1); // sector per page = 1
        id->ppaf.pln_offset = id->ppaf.sect_offset + id->ppaf.sect_len;
        id->ppaf.pln_len = fls(cpu_to_le16(grp->num_pln) - 1);
        id->ppaf.pg_offset = id->ppaf.pln_offset + id->ppaf.pln_len;
        id->ppaf.pg_len = fls(cpu_to_le16(grp->num_pg) - 1);
        id->ppaf.blk_offset = id->ppaf.pg_offset + id->ppaf.pg_len;
        id->ppaf.blk_len = fls(cpu_to_le16(grp->num_blk) - 1);
        id->ppaf.lun_offset = id->ppaf.blk_offset + id->ppaf.blk_len;
        id->ppaf.lun_len = fls(cpu_to_le16(grp->num_lun) - 1);
        id->ppaf.ch_offset = id->ppaf.lun_offset + id->ppaf.lun_len;
        id->ppaf.ch_len = fls(cpu_to_le16(grp->num_ch) - 1);
	
	grp->fpg_sz = 4096;
	grp->csecs = 4096;

	grp->trdt = 25000;
	grp->trdm = 25000;
	grp->tprt = 500000;
	grp->tprm = 500000;
	grp->tbet = 1500000;
	grp->tbem = 1500000;

	if (grp->num_pln == 1)
                grp->mpos = 0x010101; /* single plane rwe */
        else if (grp->num_pln == 2)
                grp->mpos = 0x020202;
        else if (grp->num_pln == 4)
                grp->mpos = 0x040404;
        else{
                pr_err("EMUL: unsupported mpos\n");
                BUG();
        }

	grp->cpar = hw_queue_depth;

	printk("EMUL: num_pg %d, num_blk %d, num_lun %d\n", grp->num_pg, grp->num_blk, grp->num_lun);

	return 0;
}

static void emul_end_io(struct request *rq, blk_status_t status)
{
	struct nvm_rq *rqd = rq->end_io_data;

//	printk("JJY: emul_end_io %d", rqd->ppa_addr);

	nvm_end_io(rqd);

	blk_mq_free_request(rq);
}

static int emul_submit_io(struct nvm_dev *dev, struct nvm_rq *rqd)
{
	struct request_queue *q = dev->q;
	struct request *rq;
	struct bio *bio = rqd->bio;
	int writing;

	rq = blk_mq_alloc_request(q, rqd_is_write(rqd) ? REQ_OP_DRV_OUT : REQ_OP_DRV_IN, 0);
	if(IS_ERR(rq))
		return -ENOMEM;
	
	if (bio)
		blk_init_request_from_bio(rq, bio);
	else {
		rq->ioprio = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, IOPRIO_NORM);
		rq->__data_len = 0;
	}

	rq->end_io_data = rqd;

/*	rq->cmd_type = REQ_TYPE_DRV_PRIV;

	if( bio != NULL )
		rq->ioprio = bio_prio(bio);
		
	if(bio_has_data(bio))
		rq->nr_phys_segments = bio_phys_segments(q, bio);

	rq->__data_len = bio->bi_iter.bi_size;
	rq->bio = rq->biotail = bio;

	rq->end_io_data = rqd; */

	blk_execute_rq_nowait(q, NULL, rq, 0, emul_end_io);

	return 0;
}

static void *emul_create_dma_pool(struct nvm_dev *dev, char *name)
{
	mempool_t *virtmem_pool;

	virtmem_pool = mempool_create_slab_pool(128, ppa_cache);
	if (!virtmem_pool) {
		pr_err("OCSSD emulator: Unable to create virtual memory pool\n");
		return NULL;
	}

	return virtmem_pool;
}

static void emul_destroy_dma_pool(void *pool)
{
//	pr_info("OCSSD emulator: destroy DMA pool\n");
	mempool_destroy(pool);
}

static void *emul_dev_dma_alloc(struct nvm_dev *dev, void *pool,
						gfp_t mem_flags, dma_addr_t *dma_handler)
{
//	pr_info("OCSSD emulator: allocate device DMA\n");
	return mempool_alloc(pool, mem_flags);
}

static void emul_dev_dma_free(void *pool, void *entry, dma_addr_t dma_handler)
{
//	pr_info("OCSSD emulator: free device DMA\n");
	mempool_free(entry, pool);
}

static int emul_get_bb_tbl(struct nvm_dev *dev, struct ppa_addr ppa, u8 *blks)
{
	struct nvm_geo *geo = &dev->geo;
        int size = geo->blks_per_lun * geo->plane_mode;
        void *bb_tbl = kzalloc(size, GFP_KERNEL);

        if (!bb_tbl)
                return -ENOMEM;

        memcpy(blks, bb_tbl, size);
        printk("JJY: get_bb_tbl\n");

        kfree(bb_tbl);

	return 0;
}

static int emul_set_lba_list(int lun, int blk, void *blk_lba_list, int size)
{
	if (!lba_list[lun][blk]) {
		printk("JJY: no lba list\n");
		return 0;
	}

        memcpy(lba_list[lun][blk], blk_lba_list, size);

	return 0;
}


static void *emul_get_lba_list(int lun, int blk)
{
	return lba_list[lun][blk];
}


static void emul_set_blk_dsecs(int size) {
	int i, j;

	lba_list = kzalloc(sizeof(u64**)*num_lun, GFP_KERNEL);
	for (i = 0; i < num_lun; i++) {
		lba_list[i] = kzalloc(sizeof(u64*)*num_blk, GFP_KERNEL);
		for (j = 0; j < num_blk; j++)
			lba_list[i][j] = kzalloc(size, GFP_KERNEL);
	}
	printk("JJY: set blk list");
}

static struct nvm_dev_ops emul_dev_ops = {
	.identity		= emul_id,
	.submit_io		= emul_submit_io,
	.get_bb_tbl		= emul_get_bb_tbl,

//	.set_blk_dsecs		= emul_set_blk_dsecs,
//	.set_lba_list		= emul_set_lba_list,
//	.get_lba_list		= emul_get_lba_list,

	.create_dma_pool	= emul_create_dma_pool,
	.destroy_dma_pool	= emul_destroy_dma_pool,
	.dev_dma_alloc		= emul_dev_dma_alloc,
	.dev_dma_free		= emul_dev_dma_free,

	.max_phys_sect		= 64,
};

static int setup_queues(struct emuld *emuld)
{
	emuld->queues = kzalloc(submit_queues * sizeof(struct emuld_queue), GFP_KERNEL);

	if( !emuld->queues )
		return -ENOMEM;

	emuld->nr_queues = 0;
	emuld->queue_depth = hw_queue_depth;

	return 0;
}

static void cleanup_queue(struct emuld_queue *eq)
{
	kfree(eq->tag_map);
	kfree(eq->cmds);
}

static void cleanup_queues(struct emuld *emuld)
{
	int i;

	for( i = 0 ; i < emuld->nr_queues; i++ )
		cleanup_queue(&emuld->queues[i]);

	kfree(emuld->queues);
}

// TODO
static enum hrtimer_restart emul_cmd_timer_expired(struct hrtimer *timer)
{
	end_cmd(container_of(timer, struct emuld_cmd, timer));

	return HRTIMER_NORESTART;
}


static int emul_nvm_register(struct emuld *emuld)
{
	struct nvm_dev *dev;
	int rv;

	dev = nvm_alloc_dev(0);
	if (!dev)
		return -ENOMEM;

	dev->q = emuld->q;
	memcpy(dev->name, emuld->disk_name, DISK_NAME_LEN);
	dev->ops = &emul_dev_ops;

	rv = nvm_register(dev);
	if (rv) {
		kfree(dev);
		return rv;
	}
	emuld->ndev = dev;

	printk("JJY: nvm_register\n");
	return 0;
}

static int emul_add_dev(void)
{
	struct emuld *emuld;
	int rv;

	emuld = kzalloc_node(sizeof(*emuld), GFP_KERNEL, NUMA_NO_NODE);
	if( !emuld )
	{
		rv = -ENOMEM;
		goto out;
	}

	spin_lock_init(&emuld->lock);

	// initialize radix tree root
	INIT_RADIX_TREE(&emuld->emul_pages, GFP_ATOMIC);

	rv = setup_queues(emuld);
	if( rv )
		goto out_free_emuld;

	emuld->tag_set.ops = &emul_mq_ops;
	emuld->tag_set.nr_hw_queues = submit_queues;
	emuld->tag_set.queue_depth = hw_queue_depth;
	emuld->tag_set.numa_node = home_node;
	emuld->tag_set.cmd_size = sizeof(struct emuld_cmd);
	emuld->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
	emuld->tag_set.driver_data = emuld;

	rv = blk_mq_alloc_tag_set(&emuld->tag_set);
	if( rv )
		goto out_cleanup_queues;

	emuld->q = blk_mq_init_queue(&emuld->tag_set);
	if( IS_ERR(emuld->q) ) {
		rv = -ENOMEM;
		goto out_cleanup_tags;
	}

	emuld->q->queuedata = emuld;
	queue_flag_set_unlocked(QUEUE_FLAG_NONROT, emuld->q);
	queue_flag_clear_unlocked(QUEUE_FLAG_ADD_RANDOM, emuld->q);

	mutex_lock(&lock);
	emuld->index = emuld_indexes++;				// assign the emulator device number
	mutex_unlock(&lock);

//	blk_queue_logical_block_size(emuld->q, bs);
//	blk_queue_physical_block_size(emuld->q, bs);
	blk_queue_logical_block_size(emuld->q, 512);
	blk_queue_physical_block_size(emuld->q, 4096);

	sprintf(emuld->disk_name, "emuld%d", emuld->index);

	rv = emul_nvm_register(emuld);

	if(rv)
		goto out_cleanup_blk_queue;

	mutex_lock(&lock);
	list_add_tail(&emuld->list, &emuld_list);		// insert this into linked-list of emulator devices
	mutex_unlock(&lock);

	return 0;

out_cleanup_blk_queue:
	blk_cleanup_queue(emuld->q);
out_cleanup_tags:
	blk_mq_free_tag_set(&emuld->tag_set);
out_cleanup_queues:
	cleanup_queues(emuld);
out_free_emuld:
	kfree(emuld);
out:
	return rv;
}

static void emul_del_dev(struct emuld *emuld)
{
	list_del_init(&emuld->list);

	nvm_unregister(emuld->ndev);

	blk_cleanup_queue(emuld->q);
	blk_mq_free_tag_set(&emuld->tag_set);
	cleanup_queues(emuld);

	kfree(emuld);
}

static int emul_open(struct block_device *bdev, fmode_t mode){
	printk("JJY: blkdev open\n");
	return 0;
}

static void emul_release(struct gendisk *disk, fmode_t mode){
	printk("JJY: blkdev released\n");
}

static const struct  block_device_operations emul_fops ={
	.owner		= THIS_MODULE,
	.open		= emul_open,
	.release	= emul_release,
};


static int __init emul_init(void)
{
	struct emuld *emuld;
	int ret = 0, i, j;

	printk("JJY: emul init\n");

	// TODO: submit_queues

	mutex_init(&lock);
	page_pool.head = NULL;	// TODO
	major = register_blkdev(0, "emuld");

	if( major < 0 ) {
		pr_err("OCSSD emulator: registering block device driver fail\n");
		return major;
	}

	ppa_cache = kmem_cache_create("ppa_cache", PAGE_SIZE, PAGE_SIZE, 0, NULL);
	if( !ppa_cache ) {
		pr_err("OCSSD emulator: cannot create ppa cache\n");
		ret = -ENOMEM;
		goto err_ppa;
	}

	for( i = 0 ; i < nr_devices ; i++ ) {
		ret = emul_add_dev();
		if (ret)
			goto err_dev;
	}

	pr_info("OCSSD emulator: MODULE LOADED\n");

	return 0;
err_dev:
	while( !list_empty(&emuld_list) ) {
		emuld = list_entry(emuld_list.next, struct emuld, list);
		emul_del_dev(emuld);
	}
	kmem_cache_destroy(ppa_cache);
err_ppa:
	unregister_blkdev(major, "emuld");

	return ret;
}


// TODO
static void free_page_pool(void)
{
	struct page_node *head, *temp;

	head = page_pool.head;
	if( head == NULL )
		return;

	while( head->next != NULL )
	{
		temp = head->next;
		head->next = temp->next;

		__free_page(temp->page);

		vfree(temp);
	}

	vfree(head->page);
}

static void __exit emul_exit(void)
{
	struct emuld *emuld;
	int i, j;

	unregister_blkdev(major, "emuld");

/*	
	for (i = 0; i < num_lun; i++) {
		for (j = 0; j < num_blk; j++) {
			if (lba_list[i][j])
				kfree(lba_list[i][j]);
		}
	}	

	for (i = 0; i < num_lun; i++) {
		if (lba_list[i])
			kfree(lba_list[i]);
	}

	kfree(lba_list);
*/
	mutex_lock(&lock);

	while (!list_empty(&emuld_list)) {
		emuld = list_entry(emuld_list.next, struct emuld, list);
		emul_free_pages(emuld);
		emul_del_dev(emuld);
		free_page_pool();
	}
	mutex_unlock(&lock);

	kmem_cache_destroy(ppa_cache);

	pr_info("JJY: MODULE EXIT, disk_name: %s\n", emuld->disk_name);
}

module_init(emul_init);
module_exit(emul_exit);

MODULE_AUTHOR("Jhuyeong Jhin <jjysienna@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
