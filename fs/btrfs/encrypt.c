/*
 * Copyright (C) 2017 Oracle.  All rights reserved.
 * Author: Anand Jain (anand.jain@oracle.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */
#include <linux/fscrypt_supp.h>
#include "ctree.h"
#include "btrfs_inode.h"
#include "compression.h"

static int btrfs_encrypt_pages(struct list_head *na_ws,
			struct address_space *mapping, u64 start,
			unsigned long len, struct page **pages,
			unsigned long nr_pages, unsigned long *nr_ct_pages,
			unsigned long *total_in, unsigned long *total_out,
			unsigned long na_max_out, int dont_align)
{
	int ret;
	u64 blocksize;
	unsigned long i;
	struct inode *inode;
	struct page *pt_page;
	struct page *ct_page;
	unsigned long pt_len;
	unsigned long bytes_left;

	ret = 0;
	*total_in = 0;
	*total_out = 0;
	*nr_ct_pages = 0;
	inode = mapping->host;

	blocksize = BTRFS_I(inode)->root->fs_info->sectorsize;
	if (blocksize != PAGE_SIZE) {
		pr_err("blocksize not same as page size\n");
		ASSERT(1);
	}

	bytes_left = len;
	for (i = 0; i < nr_pages; i++) {
		pt_page = find_get_page(mapping, start >> PAGE_SHIFT);
		pt_len = min(bytes_left, PAGE_SIZE);

		ct_page = fscrypt_encrypt_page(inode, pt_page, pt_len, 0,
						pt_page->index, GFP_KERNEL);
		if (IS_ERR(ct_page)) {
			ret = PTR_ERR(ct_page);
			return ret;
		}

		pages[i] = ct_page;
		*nr_ct_pages = *nr_ct_pages + 1;

		*total_in += pt_len;
		*total_out += pt_len;

		start += pt_len;
		bytes_left = bytes_left - pt_len;

		if (!bytes_left)
			break;
	}

	return ret;
}

static int btrfs_decrypt_pages(struct list_head *na_ws, unsigned char *in,
			struct page *out_page, unsigned long na_start_byte,
			size_t in_size, size_t max_out_size)
{
	int ret;
	char *out_addr;
	struct inode *inode;
	struct address_space *mapping;

	if (in_size > PAGE_SIZE || max_out_size < PAGE_SIZE) {
		printk("in_size %lu max_out_size %lu\n",
				in_size, max_out_size);
		WARN_ON("BTRFS: crypto, cant decrypt more than page size\n");
		return -EINVAL;
	}

	mapping = out_page->mapping;
	if (!mapping && !mapping->host) {
		WARN_ON("BTRFS: crypto, Need mapped pages\n");
		return -EINVAL;
	}

	inode = mapping->host;

	out_addr = kmap_atomic(out_page);
	memcpy(out_addr, in, in_size);
	kunmap_atomic(out_addr);

	ret = fscrypt_decrypt_page(inode, out_page, in_size,
				na_start_byte, out_page->index);

	if (na_start_byte) {
		pr_err("Non zero start of the page: %lu\n",
						na_start_byte);
		ASSERT(1);
	}

	return ret;
}

static int btrfs_decrypt_bio_pages(struct list_head *na_ws, struct page **in_pages,
				u64 disk_start, struct bio *orig_bio, size_t in_len)
{
	char *in;
	int ret = 0;
	int more = 0;
	struct inode *inode;
	struct page *in_page;
	struct page *out_page;
	unsigned long bytes_left;
	unsigned long total_in_pages;
	unsigned long cur_page_len;
	unsigned long processed_len = 0;
	unsigned long page_in_index = 0;
	struct address_space *mapping;
	struct bio_vec *bv;

	total_in_pages = DIV_ROUND_UP(in_len, PAGE_SIZE);

	if (na_ws) {
		pr_err("Error: does not support ws\n");
		return -EINVAL;
	}

	out_page = bio_page(orig_bio);
	mapping = out_page->mapping;
	if (!mapping && !mapping->host) {
		WARN_ON("BTRFS: crypto, need mapped page\n");
		return -EINVAL;
	}
	inode = mapping->host;

	bytes_left = in_len;
	bv = orig_bio->bi_io_vec;
	out_page = bv->bv_page;

	for (page_in_index = 0; page_in_index < total_in_pages;
						page_in_index++) {
		in_page = in_pages[page_in_index];
		cur_page_len = min(bytes_left, PAGE_SIZE);

		ret = fscrypt_decrypt_page(inode, in_page, cur_page_len,
						0, out_page->index);
		if (ret)
			return ret;
		in = kmap(in_page);
		more = btrfs_decompress_buf2page(in, processed_len,
				processed_len + cur_page_len, disk_start,
				orig_bio);
		kunmap(in_page);

		bytes_left = bytes_left - cur_page_len;
		processed_len = processed_len + cur_page_len;
		/* a bit of unhygine hack should use fscrypt_decrypt_bio_page() */
		bv++;
		out_page = bv->bv_page;
		if (!more)
			break;
	}
	zero_fill_bio(orig_bio);
	return 0;
}

const struct btrfs_compress_op btrfs_encrypt_ops = {
	.alloc_workspace	= NULL,
	.free_workspace		= NULL,
	.compress_pages		= btrfs_encrypt_pages,
	.decompress		= btrfs_decrypt_pages,
	.decompress_bio		= btrfs_decrypt_bio_pages,
};
