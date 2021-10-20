// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2011 Google, Inc.
 * Copyright (C) 2019-2021 Sultan Alsawaf <sultan@kerneltoast.com>.
 * Copyright (C) 2021 XiaoMi, Inc.
 * Copyright (c) 2011-2019, The Linux Foundation. All rights reserved.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include "ion_secure_util.h"
#include "ion_system_secure_heap.h"

struct ion_dma_buf_attachment {
	struct ion_dma_buf_attachment *next;
	struct device *dev;
	struct sg_table table;
	struct list_head list;
	struct rw_semaphore map_rwsem;
	bool dma_mapped;
};

static long ion_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
static const struct file_operations ion_fops = {
	.unlocked_ioctl = ion_ioctl,
	.compat_ioctl = ion_ioctl
};

static struct ion_device ion_dev = {
	.heaps = PLIST_HEAD_INIT(ion_dev.heaps),
	.dev = {
		.minor = MISC_DYNAMIC_MINOR,
		.name = "ion",
		.fops = &ion_fops
	}
};

static void ion_buffer_free_work(struct work_struct *work)
{
	struct ion_buffer *buffer = container_of(work, typeof(*buffer), free);
	struct ion_dma_buf_attachment *a, *next;
	struct ion_heap *heap = buffer->heap;

	msm_dma_buf_freed(&buffer->iommu_data);
	for (a = buffer->attachments; a; a = next) {
		next = a->next;
		sg_free_table(&a->table);
		kfree(a);
	}
	if (buffer->kmap_refcount)
		heap->ops->unmap_kernel(heap, buffer);
	heap->ops->free(buffer);
	kfree(buffer);
}

static struct ion_buffer *ion_buffer_create(struct ion_heap *heap, size_t len,
					    unsigned int flags)
{
	struct ion_buffer *buffer;
	int ret;

	buffer = kmalloc(sizeof(*buffer), GFP_KERNEL);
	if (!buffer)
		return ERR_PTR(-ENOMEM);

	*buffer = (typeof(*buffer)){
		.flags = flags,
		.heap = heap,
		.size = len,
		.kmap_lock = __MUTEX_INITIALIZER(buffer->kmap_lock),
		.free = __WORK_INITIALIZER(buffer->free, ion_buffer_free_work),
		.map_freelist = LIST_HEAD_INIT(buffer->map_freelist),
		.freelist_lock = __SPIN_LOCK_INITIALIZER(buffer->freelist_lock),
		.iommu_data = {
			.map_list = LIST_HEAD_INIT(buffer->iommu_data.map_list),
			.lock = __MUTEX_INITIALIZER(buffer->iommu_data.lock)
		}
	};

	ret = heap->ops->allocate(heap, buffer, len, flags);
	if (ret) {
		if (ret == -EINTR || !(heap->flags & ION_HEAP_FLAG_DEFER_FREE))
			goto free_buffer;

		drain_workqueue(heap->wq);
		if (heap->ops->allocate(heap, buffer, len, flags))
			goto free_buffer;
	}

	spin_lock(&heap->stat_lock);
	heap->num_of_buffers++;
	heap->num_of_alloc_bytes += len;
	if (heap->num_of_alloc_bytes > heap->alloc_bytes_wm)
		heap->alloc_bytes_wm = heap->num_of_alloc_bytes;
	spin_unlock(&heap->stat_lock);

	table = buffer->sg_table;
	buffer->dev = dev;
	buffer->size = len;

	buffer->dev = dev;
	buffer->size = len;
	INIT_LIST_HEAD(&buffer->attachments);
	INIT_LIST_HEAD(&buffer->vmas);
	mutex_init(&buffer->lock);

	if (IS_ENABLED(CONFIG_ION_FORCE_DMA_SYNC)) {
		int i;
		struct scatterlist *sg;

		/*
		 * this will set up dma addresses for the sglist -- it is not
		 * technically correct as per the dma api -- a specific
		 * device isn't really taking ownership here.  However, in
		 * practice on our systems the only dma_address space is
		 * physical addresses.
		 */
		for_each_sg(table->sgl, sg, table->nents, i) {
			sg_dma_address(sg) = sg_phys(sg);
			sg_dma_len(sg) = sg->length;
		}
	}

	mutex_lock(&dev->buffer_lock);
	ion_buffer_add(dev, buffer);
	mutex_unlock(&dev->buffer_lock);
	atomic_long_add(len, &heap->total_allocated);
	return buffer;

free_buffer:
	kfree(buffer);
	return ERR_PTR(ret);
}

void ion_buffer_destroy(struct ion_buffer *buffer)
{
	if (buffer->kmap_cnt > 0) {
		pr_warn_ratelimited("ION client likely missing a call to dma_buf_kunmap or dma_buf_vunmap\n");
		buffer->heap->ops->unmap_kernel(buffer->heap, buffer);
	}
	buffer->heap->ops->free(buffer);
	spin_lock(&buffer->heap->stat_lock);
	buffer->heap->num_of_buffers--;
	buffer->heap->num_of_alloc_bytes -= buffer->size;
	spin_unlock(&buffer->heap->stat_lock);

	kfree(buffer);
}

static void _ion_buffer_destroy(struct ion_buffer *buffer)
{
	struct ion_heap *heap = buffer->heap;
	struct ion_device *dev = buffer->dev;

	msm_dma_buf_freed(buffer);

	mutex_lock(&dev->buffer_lock);
	rb_erase(&buffer->node, &dev->buffers);
	mutex_unlock(&dev->buffer_lock);

	atomic_long_sub(buffer->size, &buffer->heap->total_allocated);
	if (heap->flags & ION_HEAP_FLAG_DEFER_FREE)
		ion_heap_freelist_add(heap, buffer);
	else
		ion_buffer_destroy(buffer);
}

static void *ion_buffer_kmap_get(struct ion_buffer *buffer)
{
	void *vaddr;

	if (buffer->kmap_cnt) {
		buffer->kmap_cnt++;
		return buffer->vaddr;
	}
	vaddr = buffer->heap->ops->map_kernel(buffer->heap, buffer);
	if (WARN_ONCE(vaddr == NULL,
		      "heap->ops->map_kernel should return ERR_PTR on error"))
		return ERR_PTR(-EINVAL);
	if (IS_ERR(vaddr))
		return vaddr;
	buffer->vaddr = vaddr;
	buffer->kmap_cnt++;
	return vaddr;
}

static void ion_buffer_kmap_put(struct ion_buffer *buffer)
{
	if (buffer->kmap_cnt == 0) {
		pr_warn_ratelimited("ION client likely missing a call to dma_buf_kmap or dma_buf_vmap, pid:%d\n",
				    current->pid);
		return;
	}

	buffer->kmap_cnt--;
	if (!buffer->kmap_cnt) {
		buffer->heap->ops->unmap_kernel(buffer->heap, buffer);
		buffer->vaddr = NULL;
	}
}

static struct sg_table *dup_sg_table(struct sg_table *table)
{
	struct sg_table *new_table;
	int ret, i;
	struct scatterlist *sg, *new_sg;

	new_table = kzalloc(sizeof(*new_table), GFP_KERNEL);
	if (!new_table)
		return ERR_PTR(-ENOMEM);

	ret = sg_alloc_table(new_table, table->nents, GFP_KERNEL);
	if (ret) {
		kfree(new_table);
		return ERR_PTR(-ENOMEM);
	}

	new_sg = new_table->sgl;
	for_each_sg(table->sgl, sg, table->nents, i) {
		memcpy(new_sg, sg, sizeof(*sg));
		sg_dma_address(new_sg) = 0;
		sg_dma_len(new_sg) = 0;
		new_sg = sg_next(new_sg);
	}

	return new_table;
}

static void free_duped_table(struct sg_table *table)
{
	sg_free_table(table);
	kfree(table);
}

struct ion_dma_buf_attachment {
	struct device *dev;
	struct sg_table *table;
	struct list_head list;
	bool dma_mapped;
};

static int ion_dma_buf_attach(struct dma_buf *dmabuf, struct device *dev,
				struct dma_buf_attachment *attachment)
{
	struct ion_dma_buf_attachment *a;
	struct sg_table *table;
	struct ion_buffer *buffer = dmabuf->priv;

	a = kzalloc(sizeof(*a), GFP_KERNEL);
	if (!a)
		return -ENOMEM;

	table = dup_sg_table(buffer->sg_table);
	if (IS_ERR(table)) {
		kfree(a);
		return -ENOMEM;
	}

	a->table = table;
	a->dev = dev;
	a->dma_mapped = false;
	INIT_LIST_HEAD(&a->list);

	attachment->priv = a;

	mutex_lock(&buffer->lock);
	list_add(&a->list, &buffer->attachments);
	mutex_unlock(&buffer->lock);

	return 0;
}

static void ion_dma_buf_detatch(struct dma_buf *dmabuf,
				struct dma_buf_attachment *attachment)
{
	struct ion_dma_buf_attachment *a = attachment->priv;
	struct ion_buffer *buffer = dmabuf->priv;

	mutex_lock(&buffer->lock);
	list_del(&a->list);
	mutex_unlock(&buffer->lock);
	free_duped_table(a->table);

	kfree(a);
}


static struct sg_table *ion_map_dma_buf(struct dma_buf_attachment *attachment,
					enum dma_data_direction dir)
{
	struct dma_buf *dmabuf = attachment->dmabuf;
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);
	struct ion_dma_buf_attachment *a = attachment->priv;
	int count, map_attrs = attachment->dma_map_attrs;

	if (!(buffer->flags & ION_FLAG_CACHED) ||
	    !hlos_accessible_buffer(buffer))
		map_attrs |= DMA_ATTR_SKIP_CPU_SYNC;

	down_write(&a->map_rwsem);
	if (map_attrs & DMA_ATTR_DELAYED_UNMAP)
		count = msm_dma_map_sg_attrs(attachment->dev, a->table.sgl,
					     a->table.nents, dir, dmabuf,
					     map_attrs);
	else
		count = dma_map_sg_attrs(attachment->dev, a->table.sgl,
					 a->table.nents, dir, map_attrs);
	if (count)
		a->dma_mapped = true;
	up_write(&a->map_rwsem);

	return count ? &a->table : ERR_PTR(-ENOMEM);
}

static void ion_unmap_dma_buf(struct dma_buf_attachment *attachment,
			      struct sg_table *table,
			      enum dma_data_direction dir)
{
	struct dma_buf *dmabuf = attachment->dmabuf;
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);
	struct ion_dma_buf_attachment *a = attachment->priv;
	int map_attrs = attachment->dma_map_attrs;

	if (!(buffer->flags & ION_FLAG_CACHED) ||
	    !hlos_accessible_buffer(buffer))
		map_attrs |= DMA_ATTR_SKIP_CPU_SYNC;

	down_write(&a->map_rwsem);
	if (map_attrs & DMA_ATTR_DELAYED_UNMAP)
		msm_dma_unmap_sg_attrs(attachment->dev, table->sgl,
				       table->nents, dir, dmabuf, map_attrs);
	else
		dma_unmap_sg_attrs(attachment->dev, table->sgl, table->nents,
				   dir, map_attrs);
	a->dma_mapped = false;
	up_write(&a->map_rwsem);
}

static int ion_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);
	struct ion_heap *heap = buffer->heap;

	if (!buffer->heap->ops->map_user)
		return -EINVAL;

	if (!(buffer->flags & ION_FLAG_CACHED))
		vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);

	return heap->ops->map_user(heap, buffer, vma);
}

static void ion_dma_buf_release(struct dma_buf *dmabuf)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);
	struct ion_heap *heap = buffer->heap;

	if (heap->flags & ION_HEAP_FLAG_DEFER_FREE)
		queue_work(heap->wq, &buffer->free);
	else
		ion_buffer_free_work(&buffer->free);
}

static void *ion_dma_buf_vmap(struct dma_buf *dmabuf)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);
	struct ion_heap *heap = buffer->heap;
	void *vaddr;

	if (!heap->ops->map_kernel)
		return ERR_PTR(-ENODEV);

	mutex_lock(&buffer->kmap_lock);
	if (buffer->kmap_refcount) {
		vaddr = buffer->vaddr;
		buffer->kmap_refcount++;
	} else {
		vaddr = heap->ops->map_kernel(heap, buffer);
		if (IS_ERR_OR_NULL(vaddr)) {
			vaddr = ERR_PTR(-EINVAL);
		} else {
			buffer->vaddr = vaddr;
			buffer->kmap_refcount++;
		}
	}
	mutex_unlock(&buffer->kmap_lock);

	return vaddr;
}

static void ion_dma_buf_vunmap(struct dma_buf *dmabuf, void *vaddr)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);
	struct ion_heap *heap = buffer->heap;

	mutex_lock(&buffer->kmap_lock);
	if (!--buffer->kmap_refcount)
		heap->ops->unmap_kernel(heap, buffer);
	mutex_unlock(&buffer->kmap_lock);
}

static void *ion_dma_buf_kmap(struct dma_buf *dmabuf, unsigned long offset)
{
	void *vaddr;

	vaddr = ion_dma_buf_vmap(dmabuf);
	if (IS_ERR(vaddr))
		return vaddr;

	return vaddr + offset * PAGE_SIZE;
}

static void ion_dma_buf_kunmap(struct dma_buf *dmabuf, unsigned long offset,
			       void *ptr)
{
	ion_dma_buf_vunmap(dmabuf, NULL);
}

static int ion_dup_sg_table(struct sg_table *dst, struct sg_table *src)
{
	unsigned int nents = src->nents;
	struct scatterlist *d, *s;

	if (sg_alloc_table(dst, nents, GFP_KERNEL))
		return -ENOMEM;

	for (d = dst->sgl, s = src->sgl;
	     nents > SG_MAX_SINGLE_ALLOC; nents -= SG_MAX_SINGLE_ALLOC - 1,
	     d = sg_chain_ptr(&d[SG_MAX_SINGLE_ALLOC - 1]),
	     s = sg_chain_ptr(&s[SG_MAX_SINGLE_ALLOC - 1]))
		memcpy(d, s, (SG_MAX_SINGLE_ALLOC - 1) * sizeof(*d));

	if (nents)
		memcpy(d, s, nents * sizeof(*d));

	return 0;
}

static int ion_dma_buf_attach(struct dma_buf *dmabuf, struct device *dev,
			      struct dma_buf_attachment *attachment)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);
	struct ion_dma_buf_attachment *a;

	spin_lock(&buffer->freelist_lock);
	list_for_each_entry(a, &buffer->map_freelist, list) {
		if (a->dev == dev) {
			list_del(&a->list);
			spin_unlock(&buffer->freelist_lock);
			attachment->priv = a;
			return 0;
		}
	}
	spin_unlock(&buffer->freelist_lock);

	a = kmalloc(sizeof(*a), GFP_KERNEL);
	if (!a)
		return -ENOMEM;

	if (ion_dup_sg_table(&a->table, buffer->sg_table)) {
		kfree(a);
		return -ENOMEM;
	}

	a->dev = dev;
	a->dma_mapped = false;
	a->map_rwsem = (struct rw_semaphore)__RWSEM_INITIALIZER(a->map_rwsem);
	attachment->priv = a;
	a->next = buffer->attachments;
	buffer->attachments = a;

	return 0;
}

static void ion_dma_buf_detach(struct dma_buf *dmabuf,
			       struct dma_buf_attachment *attachment)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);
	struct ion_dma_buf_attachment *a = attachment->priv;

	spin_lock(&buffer->freelist_lock);
	list_add(&a->list, &buffer->map_freelist);
	spin_unlock(&buffer->freelist_lock);
}

static int ion_dma_buf_begin_cpu_access(struct dma_buf *dmabuf,
					enum dma_data_direction dir)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);
	struct ion_dma_buf_attachment *a;

	if (!hlos_accessible_buffer(buffer))
		return -EPERM;

	if (!(buffer->flags & ION_FLAG_CACHED))
		return 0;

	for (a = buffer->attachments; a; a = a->next) {
		if (down_read_trylock(&a->map_rwsem)) {
			if (a->dma_mapped)
				dma_sync_sg_for_cpu(a->dev, a->table.sgl,
						    a->table.nents, dir);
			up_read(&a->map_rwsem);
		}
	}

	return 0;
}

static int ion_dma_buf_end_cpu_access(struct dma_buf *dmabuf,
				      enum dma_data_direction dir)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);
	struct ion_dma_buf_attachment *a;

	if (!hlos_accessible_buffer(buffer))
		return -EPERM;

	if (!(buffer->flags & ION_FLAG_CACHED))
		return 0;

	for (a = buffer->attachments; a; a = a->next) {
		if (down_read_trylock(&a->map_rwsem)) {
			if (a->dma_mapped)
				dma_sync_sg_for_device(a->dev, a->table.sgl,
						       a->table.nents, dir);
			up_read(&a->map_rwsem);
		}
	}

	return 0;
}

static void ion_sgl_sync_range(struct device *dev, struct scatterlist *sgl,
			       unsigned int nents, unsigned long offset,
			       unsigned long len, enum dma_data_direction dir,
			       bool for_cpu)
{
	dma_addr_t sg_dma_addr = sg_dma_address(sgl);
	unsigned long total = 0;
	struct scatterlist *sg;
	int i;

	for_each_sg(sgl, sg, nents, i) {
		unsigned long sg_offset, sg_left, size;

		total += sg->length;
		if (total <= offset) {
			sg_dma_addr += sg->length;
			continue;
		}

		sg_left = total - offset;
		sg_offset = sg->length - sg_left;
		size = min(len, sg_left);
		if (for_cpu)
			dma_sync_single_range_for_cpu(dev, sg_dma_addr,
						      sg_offset, size, dir);
		else
			dma_sync_single_range_for_device(dev, sg_dma_addr,
							 sg_offset, size, dir);
		len -= size;
		if (!len)
			break;

		offset += size;
		sg_dma_addr += sg->length;
	}
}

static int ion_dma_buf_begin_cpu_access_partial(struct dma_buf *dmabuf,
						enum dma_data_direction dir,
						unsigned int offset,
						unsigned int len)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);
	struct ion_dma_buf_attachment *a;
	int ret = 0;

	if (!hlos_accessible_buffer(buffer))
		return -EPERM;

	if (!(buffer->flags & ION_FLAG_CACHED))
		return 0;

	for (a = buffer->attachments; a; a = a->next) {
		if (a->table.nents > 1 && sg_next(a->table.sgl)->dma_length) {
			ret = -EINVAL;
			continue;
		}

		if (down_read_trylock(&a->map_rwsem)) {
			if (a->dma_mapped)
				ion_sgl_sync_range(a->dev, a->table.sgl,
						   a->table.nents, offset, len,
						   dir, true);
			up_read(&a->map_rwsem);
		}
	}

	return ret;
}

static int ion_dma_buf_end_cpu_access_partial(struct dma_buf *dmabuf,
					      enum dma_data_direction dir,
					      unsigned int offset,
					      unsigned int len)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);
	struct ion_dma_buf_attachment *a;
	int ret = 0;

	if (!hlos_accessible_buffer(buffer))
		return -EPERM;

	if (!(buffer->flags & ION_FLAG_CACHED))
		return 0;

	for (a = buffer->attachments; a; a = a->next) {
		if (a->table.nents > 1 && sg_next(a->table.sgl)->dma_length) {
			ret = -EINVAL;
			continue;
		}

		if (down_read_trylock(&a->map_rwsem)) {
			if (a->dma_mapped)
				ion_sgl_sync_range(a->dev, a->table.sgl,
						   a->table.nents, offset, len,
						   dir, false);
			up_read(&a->map_rwsem);
		}
	}

	return ret;
}

static int ion_dma_buf_get_flags(struct dma_buf *dmabuf, unsigned long *flags)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);

	*flags = buffer->flags;
	return 0;
}

static const struct dma_buf_ops ion_dma_buf_ops = {
	.map_dma_buf = ion_map_dma_buf,
	.unmap_dma_buf = ion_unmap_dma_buf,
	.mmap = ion_mmap,
	.release = ion_dma_buf_release,
	.attach = ion_dma_buf_attach,
	.detach = ion_dma_buf_detach,
	.begin_cpu_access = ion_dma_buf_begin_cpu_access,
	.end_cpu_access = ion_dma_buf_end_cpu_access,
	.begin_cpu_access_partial = ion_dma_buf_begin_cpu_access_partial,
	.end_cpu_access_partial = ion_dma_buf_end_cpu_access_partial,
	.map_atomic = ion_dma_buf_kmap,
	.unmap_atomic = ion_dma_buf_kunmap,
	.map = ion_dma_buf_kmap,
	.unmap = ion_dma_buf_kunmap,
	.vmap = ion_dma_buf_vmap,
	.vunmap = ion_dma_buf_vunmap,
	.get_flags = ion_dma_buf_get_flags
};

struct dma_buf *ion_alloc_dmabuf(size_t len, unsigned int heap_id_mask,
				 unsigned int flags)
{
	struct ion_device *idev = &ion_dev;
	struct dma_buf_export_info exp_info;
	struct ion_buffer *buffer = NULL;
	struct dma_buf *dmabuf;
	struct ion_heap *heap;

	len = PAGE_ALIGN(len);
	if (!len)
		return ERR_PTR(-EINVAL);

	plist_for_each_entry(heap, &idev->heaps, node) {
		if (BIT(heap->id) & heap_id_mask) {
			buffer = ion_buffer_create(heap, len, flags);
			if (!IS_ERR(buffer) || PTR_ERR(buffer) == -EINTR)
				break;
		}
	}

	if (!buffer)
		return ERR_PTR(-ENODEV);

	if (IS_ERR(buffer))
		return ERR_CAST(buffer);

	exp_info = (typeof(exp_info)){
		.ops = &ion_dma_buf_ops,
		.size = buffer->size,
		.flags = O_RDWR,
		.priv = &buffer->iommu_data
	};

	dmabuf = dma_buf_export(&exp_info);
	if (IS_ERR(dmabuf))
		ion_buffer_free_work(&buffer->free);

	return dmabuf;
}

static int ion_alloc_fd(struct ion_allocation_data *a)
{
	struct dma_buf *dmabuf;
	int fd;

	dmabuf = ion_alloc_dmabuf(a->len, a->heap_id_mask, a->flags);
	if (IS_ERR(dmabuf))
		return PTR_ERR(dmabuf);

	fd = dma_buf_fd(dmabuf, O_CLOEXEC);
	if (fd < 0)
		dma_buf_put(dmabuf);

	return fd;
}

void ion_add_heap(struct ion_device *idev, struct ion_heap *heap)
{
	struct ion_heap_data *hdata = &idev->heap_data[idev->heap_count];

	if (heap->flags & ION_HEAP_FLAG_DEFER_FREE) {
		heap->wq = alloc_workqueue("%s", WQ_UNBOUND | WQ_MEM_RECLAIM |
					   WQ_CPU_INTENSIVE, 1, heap->name);
		BUG_ON(!heap->wq);
	}

	if (heap->ops->shrink)
		ion_heap_init_shrinker(heap);

	plist_node_init(&heap->node, -heap->id);
	plist_add(&heap->node, &idev->heaps);

	strlcpy(hdata->name, heap->name, sizeof(hdata->name));
	hdata->type = heap->type;
	hdata->heap_id = heap->id;
	idev->heap_count++;
}

static int ion_walk_heaps(int heap_id, int type, void *data,
			  int (*f)(struct ion_heap *heap, void *data))
{
	struct ion_device *idev = &ion_dev;
	struct ion_heap *heap;
	int ret = 0;

	plist_for_each_entry(heap, &idev->heaps, node) {
		if (heap->type == type && ION_HEAP(heap->id) == heap_id) {
			ret = f(heap, data);
			break;
		}
	}

	return ret;
}

static const struct file_operations ion_fops = {
	.owner          = THIS_MODULE,
	.unlocked_ioctl = ion_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= ion_ioctl,
#endif
};

static int ion_debug_heap_show(struct seq_file *s, void *unused)
{
	struct ion_heap *heap = s->private;

	seq_puts(s, "----------------------------------------------------\n");
	seq_printf(s, "%25s %16zu\n", "num_of_alloc_bytes ", heap->num_of_alloc_bytes);
	seq_printf(s, "%25s %16zu\n", "num_of_buffers ", heap->num_of_buffers);
	seq_printf(s, "%25s %16zu\n", "alloc_bytes_wm ", heap->alloc_bytes_wm);
	if (heap->flags & ION_HEAP_FLAG_DEFER_FREE)
		seq_printf(s, "%25s %16zu\n", "deferred free ", heap->free_list_size);
	seq_puts(s, "----------------------------------------------------\n");

	if (heap->debug_show)
		heap->debug_show(heap, s, unused);

	return 0;
}

static int ion_debug_heap_open(struct inode *inode, struct file *file)
{
	return single_open(file, ion_debug_heap_show, inode->i_private);
}

static const struct file_operations debug_heap_fops = {
	.open = ion_debug_heap_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int debug_shrink_set(void *data, u64 val)
{
	struct ion_device *idev = &ion_dev;

	if (!query->cnt)
		return -EINVAL;

	if (copy_to_user(u64_to_user_ptr(query->heaps), idev->heap_data,
			 min(query->cnt, idev->heap_count) *
			 sizeof(*idev->heap_data)))
		return -EFAULT;

	return 0;
}

static long ion_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct dentry *debug_file;
	struct dentry *heap_root;
	char debug_name[64];

	if (!heap->ops->allocate || !heap->ops->free)
		pr_err("%s: can not add heap with invalid ops struct.\n",
		       __func__);

	spin_lock_init(&heap->free_lock);
	spin_lock_init(&heap->stat_lock);
	heap->free_list_size = 0;

	switch (cmd) {
	case ION_IOC_ALLOC:
		if (copy_from_user(&data, (void __user *)arg,
				   sizeof(struct ion_allocation_data)))
			return -EFAULT;

		fd = ion_alloc_fd(&data.allocation);
		if (fd < 0)
			return fd;

	heap->dev = dev;
	heap->num_of_buffers = 0;
	heap->num_of_alloc_bytes = 0;
	heap->alloc_bytes_wm = 0;

	debug_file = debugfs_create_file(heap->name, 0664,
					dev->heaps_debug_root, heap,
					&debug_heap_fops);

	if (!debug_file) {
		char buf[256], *path;

		path = dentry_path(dev->heaps_debug_root, buf, 256);
		pr_err("Failed to create heap debugfs at %s/%s\n",
			path, heap->name);
	}

	heap_root = debugfs_create_dir(heap->name, dev->debug_root);
	debugfs_create_u64("num_of_buffers",
			   0444, heap_root,
			   &heap->num_of_buffers);
	debugfs_create_u64("num_of_alloc_bytes",
			   0444,
			   heap_root,
			   &heap->num_of_alloc_bytes);
	debugfs_create_u64("alloc_bytes_wm",
			   0444,
			   heap_root,
			   &heap->alloc_bytes_wm);

	if (heap->shrinker.count_objects &&
	    heap->shrinker.scan_objects) {
		snprintf(debug_name, 64, "%s_shrink", heap->name);
		debugfs_create_file(debug_name,
				    0644,
				    heap_root,
				    heap,
				    &debug_shrink_fops);
	}

	down_write(&dev->lock);
	/*
	 * use negative heap->id to reverse the priority -- when traversing
	 * the list later attempt higher id numbers first
	 */
	plist_node_init(&heap->node, -heap->id);
	plist_add(&heap->node, &dev->heaps);

	dev->heap_cnt++;
	up_write(&dev->lock);
}

struct ion_device *ion_device_create(struct ion_heap_data *heap_data)
{
	struct ion_device *idev = &ion_dev;
	int ret;

	ret = misc_register(&idev->dev);
	if (ret)
		return ERR_PTR(ret);
	}

	idev->debug_root = debugfs_create_dir("ion", NULL);
	if (!idev->debug_root) {
		pr_err("ion: failed to create debugfs root directory.\n");
		goto debugfs_done;
	}
	idev->heaps_debug_root = debugfs_create_dir("heaps", idev->debug_root);
	if (!idev->heaps_debug_root) {
		pr_err("ion: failed to create debugfs heaps directory.\n");
		goto debugfs_done;
	}

debugfs_done:

	idev->heap_data = heap_data;
	return idev;
}
