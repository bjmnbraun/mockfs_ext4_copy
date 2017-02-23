/*
 *  linux/fs/mockfs/indirect.c
 *
 *  from
 *
 *  linux/fs/mockfs/inode.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/inode.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Goal-directed block allocation by Stephen Tweedie
 *	(sct@redhat.com), 1993, 1998
 */

#include "mockfs_jbd2.h"
#include "truncate.h"
#include <linux/dax.h>
#include <linux/uio.h>


typedef struct {
	__le32	*p;
	__le32	key;
	struct buffer_head *bh;
} Indirect;

static inline void add_chain(Indirect *p, struct buffer_head *bh, __le32 *v)
{
	p->key = *(p->p = v);
	p->bh = bh;
}

/**
 *	mockfs_block_to_path - parse the block number into array of offsets
 *	@inode: inode in question (we are only interested in its superblock)
 *	@i_block: block number to be parsed
 *	@offsets: array to store the offsets in
 *	@boundary: set this non-zero if the referred-to block is likely to be
 *	       followed (on disk) by an indirect block.
 *
 *	To store the locations of file's data mockfs uses a data structure common
 *	for UNIX filesystems - tree of pointers anchored in the inode, with
 *	data blocks at leaves and indirect blocks in intermediate nodes.
 *	This function translates the block number into path in that tree -
 *	return value is the path length and @offsets[n] is the offset of
 *	pointer to (n+1)th node in the nth one. If @block is out of range
 *	(negative or too large) warning is printed and zero returned.
 *
 *	Note: function doesn't find node addresses, so no IO is needed. All
 *	we need to know is the capacity of indirect blocks (taken from the
 *	inode->i_sb).
 */

/*
 * Portability note: the last comparison (check that we fit into triple
 * indirect block) is spelled differently, because otherwise on an
 * architecture with 32-bit longs and 8Kb pages we might get into trouble
 * if our filesystem had 8Kb blocks. We might use long long, but that would
 * kill us on x86. Oh, well, at least the sign propagation does not matter -
 * i_block would have to be negative in the very beginning, so we would not
 * get there at all.
 */

static int mockfs_block_to_path(struct inode *inode,
			      mockfs_lblk_t i_block,
			      mockfs_lblk_t offsets[4], int *boundary)
{
	int ptrs = MOCKFS_ADDR_PER_BLOCK(inode->i_sb);
	int ptrs_bits = MOCKFS_ADDR_PER_BLOCK_BITS(inode->i_sb);
	const long direct_blocks = MOCKFS_NDIR_BLOCKS,
		indirect_blocks = ptrs,
		double_blocks = (1 << (ptrs_bits * 2));
	int n = 0;
	int final = 0;

	if (i_block < direct_blocks) {
		offsets[n++] = i_block;
		final = direct_blocks;
	} else if ((i_block -= direct_blocks) < indirect_blocks) {
		offsets[n++] = MOCKFS_IND_BLOCK;
		offsets[n++] = i_block;
		final = ptrs;
	} else if ((i_block -= indirect_blocks) < double_blocks) {
		offsets[n++] = MOCKFS_DIND_BLOCK;
		offsets[n++] = i_block >> ptrs_bits;
		offsets[n++] = i_block & (ptrs - 1);
		final = ptrs;
	} else if (((i_block -= double_blocks) >> (ptrs_bits * 2)) < ptrs) {
		offsets[n++] = MOCKFS_TIND_BLOCK;
		offsets[n++] = i_block >> (ptrs_bits * 2);
		offsets[n++] = (i_block >> ptrs_bits) & (ptrs - 1);
		offsets[n++] = i_block & (ptrs - 1);
		final = ptrs;
	} else {
		mockfs_warning(inode->i_sb, "block %lu > max in inode %lu",
			     i_block + direct_blocks +
			     indirect_blocks + double_blocks, inode->i_ino);
	}
	if (boundary)
		*boundary = final - 1 - (i_block & (ptrs - 1));
	return n;
}

/**
 *	mockfs_get_branch - read the chain of indirect blocks leading to data
 *	@inode: inode in question
 *	@depth: depth of the chain (1 - direct pointer, etc.)
 *	@offsets: offsets of pointers in inode/indirect blocks
 *	@chain: place to store the result
 *	@err: here we store the error value
 *
 *	Function fills the array of triples <key, p, bh> and returns %NULL
 *	if everything went OK or the pointer to the last filled triple
 *	(incomplete one) otherwise. Upon the return chain[i].key contains
 *	the number of (i+1)-th block in the chain (as it is stored in memory,
 *	i.e. little-endian 32-bit), chain[i].p contains the address of that
 *	number (it points into struct inode for i==0 and into the bh->b_data
 *	for i>0) and chain[i].bh points to the buffer_head of i-th indirect
 *	block for i>0 and NULL for i==0. In other words, it holds the block
 *	numbers of the chain, addresses they were taken from (and where we can
 *	verify that chain did not change) and buffer_heads hosting these
 *	numbers.
 *
 *	Function stops when it stumbles upon zero pointer (absent block)
 *		(pointer to last triple returned, *@err == 0)
 *	or when it gets an IO error reading an indirect block
 *		(ditto, *@err == -EIO)
 *	or when it reads all @depth-1 indirect blocks successfully and finds
 *	the whole chain, all way to the data (returns %NULL, *err == 0).
 *
 *      Need to be called with
 *      down_read(&MOCKFS_I(inode)->i_data_sem)
 */
static Indirect *mockfs_get_branch(struct inode *inode, int depth,
				 mockfs_lblk_t  *offsets,
				 Indirect chain[4], int *err)
{
	struct super_block *sb = inode->i_sb;
	Indirect *p = chain;
	struct buffer_head *bh;
	int ret = -EIO;

	*err = 0;
	/* i_data is not going away, no lock needed */
	add_chain(chain, NULL, MOCKFS_I(inode)->i_data + *offsets);
	if (!p->key)
		goto no_block;
	while (--depth) {
		bh = sb_getblk(sb, le32_to_cpu(p->key));
		if (unlikely(!bh)) {
			ret = -ENOMEM;
			goto failure;
		}

		if (!bh_uptodate_or_lock(bh)) {
			if (bh_submit_read(bh) < 0) {
				put_bh(bh);
				goto failure;
			}
			/* validate block references */
			if (mockfs_check_indirect_blockref(inode, bh)) {
				put_bh(bh);
				goto failure;
			}
		}

		add_chain(++p, bh, (__le32 *)bh->b_data + *++offsets);
		/* Reader: end */
		if (!p->key)
			goto no_block;
	}
	return NULL;

failure:
	*err = ret;
no_block:
	return p;
}

/**
 *	mockfs_find_near - find a place for allocation with sufficient locality
 *	@inode: owner
 *	@ind: descriptor of indirect block.
 *
 *	This function returns the preferred place for block allocation.
 *	It is used when heuristic for sequential allocation fails.
 *	Rules are:
 *	  + if there is a block to the left of our position - allocate near it.
 *	  + if pointer will live in indirect block - allocate near that block.
 *	  + if pointer will live in inode - allocate in the same
 *	    cylinder group.
 *
 * In the latter case we colour the starting block by the callers PID to
 * prevent it from clashing with concurrent allocations for a different inode
 * in the same block group.   The PID is used here so that functionally related
 * files will be close-by on-disk.
 *
 *	Caller must make sure that @ind is valid and will stay that way.
 */
static mockfs_fsblk_t mockfs_find_near(struct inode *inode, Indirect *ind)
{
	struct mockfs_inode_info *ei = MOCKFS_I(inode);
	__le32 *start = ind->bh ? (__le32 *) ind->bh->b_data : ei->i_data;
	__le32 *p;

	/* Try to find previous block */
	for (p = ind->p - 1; p >= start; p--) {
		if (*p)
			return le32_to_cpu(*p);
	}

	/* No such thing, so let's try location of indirect block */
	if (ind->bh)
		return ind->bh->b_blocknr;

	/*
	 * It is going to be referred to from the inode itself? OK, just put it
	 * into the same cylinder group then.
	 */
	return mockfs_inode_to_goal_block(inode);
}

/**
 *	mockfs_find_goal - find a preferred place for allocation.
 *	@inode: owner
 *	@block:  block we want
 *	@partial: pointer to the last triple within a chain
 *
 *	Normally this function find the preferred place for block allocation,
 *	returns it.
 *	Because this is only used for non-extent files, we limit the block nr
 *	to 32 bits.
 */
static mockfs_fsblk_t mockfs_find_goal(struct inode *inode, mockfs_lblk_t block,
				   Indirect *partial)
{
	mockfs_fsblk_t goal;

	/*
	 * XXX need to get goal block from mballoc's data structures
	 */

	goal = mockfs_find_near(inode, partial);
	goal = goal & MOCKFS_MAX_BLOCK_FILE_PHYS;
	return goal;
}

/**
 *	mockfs_blks_to_allocate - Look up the block map and count the number
 *	of direct blocks need to be allocated for the given branch.
 *
 *	@branch: chain of indirect blocks
 *	@k: number of blocks need for indirect blocks
 *	@blks: number of data blocks to be mapped.
 *	@blocks_to_boundary:  the offset in the indirect block
 *
 *	return the total number of blocks to be allocate, including the
 *	direct and indirect blocks.
 */
static int mockfs_blks_to_allocate(Indirect *branch, int k, unsigned int blks,
				 int blocks_to_boundary)
{
	unsigned int count = 0;

	/*
	 * Simple case, [t,d]Indirect block(s) has not allocated yet
	 * then it's clear blocks on that path have not allocated
	 */
	if (k > 0) {
		/* right now we don't handle cross boundary allocation */
		if (blks < blocks_to_boundary + 1)
			count += blks;
		else
			count += blocks_to_boundary + 1;
		return count;
	}

	count++;
	while (count < blks && count <= blocks_to_boundary &&
		le32_to_cpu(*(branch[0].p + count)) == 0) {
		count++;
	}
	return count;
}

/**
 *	mockfs_alloc_branch - allocate and set up a chain of blocks.
 *	@handle: handle for this transaction
 *	@inode: owner
 *	@indirect_blks: number of allocated indirect blocks
 *	@blks: number of allocated direct blocks
 *	@goal: preferred place for allocation
 *	@offsets: offsets (in the blocks) to store the pointers to next.
 *	@branch: place to store the chain in.
 *
 *	This function allocates blocks, zeroes out all but the last one,
 *	links them into chain and (if we are synchronous) writes them to disk.
 *	In other words, it prepares a branch that can be spliced onto the
 *	inode. It stores the information about that chain in the branch[], in
 *	the same format as mockfs_get_branch() would do. We are calling it after
 *	we had read the existing part of chain and partial points to the last
 *	triple of that (one with zero ->key). Upon the exit we have the same
 *	picture as after the successful mockfs_get_block(), except that in one
 *	place chain is disconnected - *branch->p is still zero (we did not
 *	set the last link), but branch->key contains the number that should
 *	be placed into *branch->p to fill that gap.
 *
 *	If allocation fails we free all blocks we've allocated (and forget
 *	their buffer_heads) and return the error value the from failed
 *	mockfs_alloc_block() (normally -ENOSPC). Otherwise we set the chain
 *	as described above and return 0.
 */
static int mockfs_alloc_branch(handle_t *handle,
			     struct mockfs_allocation_request *ar,
			     int indirect_blks, mockfs_lblk_t *offsets,
			     Indirect *branch)
{
	struct buffer_head *		bh;
	mockfs_fsblk_t			b, new_blocks[4];
	__le32				*p;
	int				i, j, err, len = 1;

	for (i = 0; i <= indirect_blks; i++) {
		if (i == indirect_blks) {
			new_blocks[i] = mockfs_mb_new_blocks(handle, ar, &err);
		} else
			ar->goal = new_blocks[i] = mockfs_new_meta_blocks(handle,
					ar->inode, ar->goal,
					ar->flags & MOCKFS_MB_DELALLOC_RESERVED,
					NULL, &err);
		if (err) {
			i--;
			goto failed;
		}
		branch[i].key = cpu_to_le32(new_blocks[i]);
		if (i == 0)
			continue;

		bh = branch[i].bh = sb_getblk(ar->inode->i_sb, new_blocks[i-1]);
		if (unlikely(!bh)) {
			err = -ENOMEM;
			goto failed;
		}
		lock_buffer(bh);
		BUFFER_TRACE(bh, "call get_create_access");
		err = mockfs_journal_get_create_access(handle, bh);
		if (err) {
			unlock_buffer(bh);
			goto failed;
		}

		memset(bh->b_data, 0, bh->b_size);
		p = branch[i].p = (__le32 *) bh->b_data + offsets[i];
		b = new_blocks[i];

		if (i == indirect_blks)
			len = ar->len;
		for (j = 0; j < len; j++)
			*p++ = cpu_to_le32(b++);

		BUFFER_TRACE(bh, "marking uptodate");
		set_buffer_uptodate(bh);
		unlock_buffer(bh);

		BUFFER_TRACE(bh, "call mockfs_handle_dirty_metadata");
		err = mockfs_handle_dirty_metadata(handle, ar->inode, bh);
		if (err)
			goto failed;
	}
	return 0;
failed:
	for (; i >= 0; i--) {
		/*
		 * We want to mockfs_forget() only freshly allocated indirect
		 * blocks.  Buffer for new_blocks[i-1] is at branch[i].bh and
		 * buffer at branch[0].bh is indirect block / inode already
		 * existing before mockfs_alloc_branch() was called.
		 */
		if (i > 0 && i != indirect_blks && branch[i].bh)
			mockfs_forget(handle, 1, ar->inode, branch[i].bh,
				    branch[i].bh->b_blocknr);
		mockfs_free_blocks(handle, ar->inode, NULL, new_blocks[i],
				 (i == indirect_blks) ? ar->len : 1, 0);
	}
	return err;
}

/**
 * mockfs_splice_branch - splice the allocated branch onto inode.
 * @handle: handle for this transaction
 * @inode: owner
 * @block: (logical) number of block we are adding
 * @chain: chain of indirect blocks (with a missing link - see
 *	mockfs_alloc_branch)
 * @where: location of missing link
 * @num:   number of indirect blocks we are adding
 * @blks:  number of direct blocks we are adding
 *
 * This function fills the missing link and does all housekeeping needed in
 * inode (->i_blocks, etc.). In case of success we end up with the full
 * chain to new block and return 0.
 */
static int mockfs_splice_branch(handle_t *handle,
			      struct mockfs_allocation_request *ar,
			      Indirect *where, int num)
{
	int i;
	int err = 0;
	mockfs_fsblk_t current_block;

	/*
	 * If we're splicing into a [td]indirect block (as opposed to the
	 * inode) then we need to get write access to the [td]indirect block
	 * before the splice.
	 */
	if (where->bh) {
		BUFFER_TRACE(where->bh, "get_write_access");
		err = mockfs_journal_get_write_access(handle, where->bh);
		if (err)
			goto err_out;
	}
	/* That's it */

	*where->p = where->key;

	/*
	 * Update the host buffer_head or inode to point to more just allocated
	 * direct blocks blocks
	 */
	if (num == 0 && ar->len > 1) {
		current_block = le32_to_cpu(where->key) + 1;
		for (i = 1; i < ar->len; i++)
			*(where->p + i) = cpu_to_le32(current_block++);
	}

	/* We are done with atomic stuff, now do the rest of housekeeping */
	/* had we spliced it onto indirect block? */
	if (where->bh) {
		/*
		 * If we spliced it onto an indirect block, we haven't
		 * altered the inode.  Note however that if it is being spliced
		 * onto an indirect block at the very end of the file (the
		 * file is growing) then we *will* alter the inode to reflect
		 * the new i_size.  But that is not done here - it is done in
		 * generic_commit_write->__mark_inode_dirty->mockfs_dirty_inode.
		 */
		jbd_debug(5, "splicing indirect only\n");
		BUFFER_TRACE(where->bh, "call mockfs_handle_dirty_metadata");
		err = mockfs_handle_dirty_metadata(handle, ar->inode, where->bh);
		if (err)
			goto err_out;
	} else {
		/*
		 * OK, we spliced it into the inode itself on a direct block.
		 */
		mockfs_mark_inode_dirty(handle, ar->inode);
		jbd_debug(5, "splicing direct\n");
	}
	return err;

err_out:
	for (i = 1; i <= num; i++) {
		/*
		 * branch[i].bh is newly allocated, so there is no
		 * need to revoke the block, which is why we don't
		 * need to set MOCKFS_FREE_BLOCKS_METADATA.
		 */
		mockfs_free_blocks(handle, ar->inode, where[i].bh, 0, 1,
				 MOCKFS_FREE_BLOCKS_FORGET);
	}
	mockfs_free_blocks(handle, ar->inode, NULL, le32_to_cpu(where[num].key),
			 ar->len, 0);

	return err;
}

/*
 * The mockfs_ind_map_blocks() function handles non-extents inodes
 * (i.e., using the traditional indirect/double-indirect i_blocks
 * scheme) for mockfs_map_blocks().
 *
 * Allocation strategy is simple: if we have to allocate something, we will
 * have to go the whole way to leaf. So let's do it before attaching anything
 * to tree, set linkage between the newborn blocks, write them if sync is
 * required, recheck the path, free and repeat if check fails, otherwise
 * set the last missing link (that will protect us from any truncate-generated
 * removals - all blocks on the path are immune now) and possibly force the
 * write on the parent block.
 * That has a nice additional property: no special recovery from the failed
 * allocations is needed - we simply release blocks and do not touch anything
 * reachable from inode.
 *
 * `handle' can be NULL if create == 0.
 *
 * return > 0, # of blocks mapped or allocated.
 * return = 0, if plain lookup failed.
 * return < 0, error case.
 *
 * The mockfs_ind_get_blocks() function should be called with
 * down_write(&MOCKFS_I(inode)->i_data_sem) if allocating filesystem
 * blocks (i.e., flags has MOCKFS_GET_BLOCKS_CREATE set) or
 * down_read(&MOCKFS_I(inode)->i_data_sem) if not allocating file system
 * blocks.
 */
int mockfs_ind_map_blocks(handle_t *handle, struct inode *inode,
			struct mockfs_map_blocks *map,
			int flags)
{
	struct mockfs_allocation_request ar;
	int err = -EIO;
	mockfs_lblk_t offsets[4];
	Indirect chain[4];
	Indirect *partial;
	int indirect_blks;
	int blocks_to_boundary = 0;
	int depth;
	int count = 0;
	mockfs_fsblk_t first_block = 0;

	J_ASSERT(!(mockfs_test_inode_flag(inode, MOCKFS_INODE_EXTENTS)));
	J_ASSERT(handle != NULL || (flags & MOCKFS_GET_BLOCKS_CREATE) == 0);
	depth = mockfs_block_to_path(inode, map->m_lblk, offsets,
				   &blocks_to_boundary);

	if (depth == 0)
		goto out;

	partial = mockfs_get_branch(inode, depth, offsets, chain, &err);

	/* Simplest case - block found, no allocation needed */
	if (!partial) {
		first_block = le32_to_cpu(chain[depth - 1].key);
		count++;
		/*map more blocks*/
		while (count < map->m_len && count <= blocks_to_boundary) {
			mockfs_fsblk_t blk;

			blk = le32_to_cpu(*(chain[depth-1].p + count));

			if (blk == first_block + count)
				count++;
			else
				break;
		}
		goto got_it;
	}

	/* Next simple case - plain lookup failed */
	if ((flags & MOCKFS_GET_BLOCKS_CREATE) == 0) {
		unsigned epb = inode->i_sb->s_blocksize / sizeof(u32);
		int i;

		/* Count number blocks in a subtree under 'partial' */
		count = 1;
		for (i = 0; partial + i != chain + depth - 1; i++)
			count *= epb;
		/* Fill in size of a hole we found */
		map->m_pblk = 0;
		map->m_len = min_t(unsigned int, map->m_len, count);
		goto cleanup;
	}

	/* Failed read of indirect block */
	if (err == -EIO)
		goto cleanup;

	/*
	 * Okay, we need to do block allocation.
	*/
	if (mockfs_has_feature_bigalloc(inode->i_sb)) {
		MOCKFS_ERROR_INODE(inode, "Can't allocate blocks for "
				 "non-extent mapped inodes with bigalloc");
		return -EFSCORRUPTED;
	}

	/* Set up for the direct block allocation */
	memset(&ar, 0, sizeof(ar));
	ar.inode = inode;
	ar.logical = map->m_lblk;
	if (S_ISREG(inode->i_mode))
		ar.flags = MOCKFS_MB_HINT_DATA;
	if (flags & MOCKFS_GET_BLOCKS_DELALLOC_RESERVE)
		ar.flags |= MOCKFS_MB_DELALLOC_RESERVED;
	if (flags & MOCKFS_GET_BLOCKS_METADATA_NOFAIL)
		ar.flags |= MOCKFS_MB_USE_RESERVED;

	ar.goal = mockfs_find_goal(inode, map->m_lblk, partial);

	/* the number of blocks need to allocate for [d,t]indirect blocks */
	indirect_blks = (chain + depth) - partial - 1;

	/*
	 * Next look up the indirect map to count the totoal number of
	 * direct blocks to allocate for this branch.
	 */
	ar.len = mockfs_blks_to_allocate(partial, indirect_blks,
				       map->m_len, blocks_to_boundary);

	/*
	 * Block out mockfs_truncate while we alter the tree
	 */
	err = mockfs_alloc_branch(handle, &ar, indirect_blks,
				offsets + (partial - chain), partial);

	/*
	 * The mockfs_splice_branch call will free and forget any buffers
	 * on the new chain if there is a failure, but that risks using
	 * up transaction credits, especially for bitmaps where the
	 * credits cannot be returned.  Can we handle this somehow?  We
	 * may need to return -EAGAIN upwards in the worst case.  --sct
	 */
	if (!err)
		err = mockfs_splice_branch(handle, &ar, partial, indirect_blks);
	if (err)
		goto cleanup;

	map->m_flags |= MOCKFS_MAP_NEW;

	mockfs_update_inode_fsync_trans(handle, inode, 1);
	count = ar.len;
got_it:
	map->m_flags |= MOCKFS_MAP_MAPPED;
	map->m_pblk = le32_to_cpu(chain[depth-1].key);
	map->m_len = count;
	if (count > blocks_to_boundary)
		map->m_flags |= MOCKFS_MAP_BOUNDARY;
	err = count;
	/* Clean up and exit */
	partial = chain + depth - 1;	/* the whole chain */
cleanup:
	while (partial > chain) {
		BUFFER_TRACE(partial->bh, "call brelse");
		brelse(partial->bh);
		partial--;
	}
out:
	return err;
}

/*
 * O_DIRECT for ext3 (or indirect map) based files
 *
 * If the O_DIRECT write will extend the file then add this inode to the
 * orphan list.  So recovery will truncate it back to the original size
 * if the machine crashes during the write.
 *
 * If the O_DIRECT write is intantiating holes inside i_size and the machine
 * crashes then stale disk data _may_ be exposed inside the file. But current
 * VFS code falls back into buffered path in that case so we are safe.
 */
ssize_t mockfs_ind_direct_IO(struct kiocb *iocb, struct iov_iter *iter,
			   loff_t offset)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	struct mockfs_inode_info *ei = MOCKFS_I(inode);
	handle_t *handle;
	ssize_t ret;
	int orphan = 0;
	size_t count = iov_iter_count(iter);
	int retries = 0;

	if (iov_iter_rw(iter) == WRITE) {
		loff_t final_size = offset + count;

		if (final_size > inode->i_size) {
			/* Credits for sb + inode write */
			handle = mockfs_journal_start(inode, MOCKFS_HT_INODE, 2);
			if (IS_ERR(handle)) {
				ret = PTR_ERR(handle);
				goto out;
			}
			ret = mockfs_orphan_add(handle, inode);
			if (ret) {
				mockfs_journal_stop(handle);
				goto out;
			}
			orphan = 1;
			ei->i_disksize = inode->i_size;
			mockfs_journal_stop(handle);
		}
	}

retry:
	if (iov_iter_rw(iter) == READ && mockfs_should_dioread_nolock(inode)) {
		/*
		 * Nolock dioread optimization may be dynamically disabled
		 * via mockfs_inode_block_unlocked_dio(). Check inode's state
		 * while holding extra i_dio_count ref.
		 */
		inode_dio_begin(inode);
		smp_mb();
		if (unlikely(mockfs_test_inode_state(inode,
						    MOCKFS_STATE_DIOREAD_LOCK))) {
			inode_dio_end(inode);
			goto locked;
		}
		if (IS_DAX(inode))
			ret = dax_do_io(iocb, inode, iter, offset,
					mockfs_dio_get_block, NULL, 0);
		else
			ret = __blockdev_direct_IO(iocb, inode,
						   inode->i_sb->s_bdev, iter,
						   offset, mockfs_dio_get_block,
						   NULL, NULL, 0);
		inode_dio_end(inode);
	} else {
locked:
		if (IS_DAX(inode))
			ret = dax_do_io(iocb, inode, iter, offset,
					mockfs_dio_get_block, NULL, DIO_LOCKING);
		else
			ret = blockdev_direct_IO(iocb, inode, iter, offset,
						 mockfs_dio_get_block);

		if (unlikely(iov_iter_rw(iter) == WRITE && ret < 0)) {
			loff_t isize = i_size_read(inode);
			loff_t end = offset + count;

			if (end > isize)
				mockfs_truncate_failed_write(inode);
		}
	}
	if (ret == -ENOSPC && mockfs_should_retry_alloc(inode->i_sb, &retries))
		goto retry;

	if (orphan) {
		int err;

		/* Credits for sb + inode write */
		handle = mockfs_journal_start(inode, MOCKFS_HT_INODE, 2);
		if (IS_ERR(handle)) {
			/* This is really bad luck. We've written the data
			 * but cannot extend i_size. Bail out and pretend
			 * the write failed... */
			ret = PTR_ERR(handle);
			if (inode->i_nlink)
				mockfs_orphan_del(NULL, inode);

			goto out;
		}
		if (inode->i_nlink)
			mockfs_orphan_del(handle, inode);
		if (ret > 0) {
			loff_t end = offset + ret;
			if (end > inode->i_size) {
				ei->i_disksize = end;
				i_size_write(inode, end);
				/*
				 * We're going to return a positive `ret'
				 * here due to non-zero-length I/O, so there's
				 * no way of reporting error returns from
				 * mockfs_mark_inode_dirty() to userspace.  So
				 * ignore it.
				 */
				mockfs_mark_inode_dirty(handle, inode);
			}
		}
		err = mockfs_journal_stop(handle);
		if (ret == 0)
			ret = err;
	}
out:
	return ret;
}

/*
 * Calculate the number of metadata blocks need to reserve
 * to allocate a new block at @lblocks for non extent file based file
 */
int mockfs_ind_calc_metadata_amount(struct inode *inode, sector_t lblock)
{
	struct mockfs_inode_info *ei = MOCKFS_I(inode);
	sector_t dind_mask = ~((sector_t)MOCKFS_ADDR_PER_BLOCK(inode->i_sb) - 1);
	int blk_bits;

	if (lblock < MOCKFS_NDIR_BLOCKS)
		return 0;

	lblock -= MOCKFS_NDIR_BLOCKS;

	if (ei->i_da_metadata_calc_len &&
	    (lblock & dind_mask) == ei->i_da_metadata_calc_last_lblock) {
		ei->i_da_metadata_calc_len++;
		return 0;
	}
	ei->i_da_metadata_calc_last_lblock = lblock & dind_mask;
	ei->i_da_metadata_calc_len = 1;
	blk_bits = order_base_2(lblock);
	return (blk_bits / MOCKFS_ADDR_PER_BLOCK_BITS(inode->i_sb)) + 1;
}

/*
 * Calculate number of indirect blocks touched by mapping @nrblocks logically
 * contiguous blocks
 */
int mockfs_ind_trans_blocks(struct inode *inode, int nrblocks)
{
	/*
	 * With N contiguous data blocks, we need at most
	 * N/MOCKFS_ADDR_PER_BLOCK(inode->i_sb) + 1 indirect blocks,
	 * 2 dindirect blocks, and 1 tindirect block
	 */
	return DIV_ROUND_UP(nrblocks, MOCKFS_ADDR_PER_BLOCK(inode->i_sb)) + 4;
}

/*
 * Truncate transactions can be complex and absolutely huge.  So we need to
 * be able to restart the transaction at a conventient checkpoint to make
 * sure we don't overflow the journal.
 *
 * Try to extend this transaction for the purposes of truncation.  If
 * extend fails, we need to propagate the failure up and restart the
 * transaction in the top-level truncate loop. --sct
 *
 * Returns 0 if we managed to create more room.  If we can't create more
 * room, and the transaction must be restarted we return 1.
 */
static int try_to_extend_transaction(handle_t *handle, struct inode *inode)
{
	if (!mockfs_handle_valid(handle))
		return 0;
	if (mockfs_handle_has_enough_credits(handle, MOCKFS_RESERVE_TRANS_BLOCKS+1))
		return 0;
	if (!mockfs_journal_extend(handle, mockfs_blocks_for_truncate(inode)))
		return 0;
	return 1;
}

/*
 * Probably it should be a library function... search for first non-zero word
 * or memcmp with zero_page, whatever is better for particular architecture.
 * Linus?
 */
static inline int all_zeroes(__le32 *p, __le32 *q)
{
	while (p < q)
		if (*p++)
			return 0;
	return 1;
}

/**
 *	mockfs_find_shared - find the indirect blocks for partial truncation.
 *	@inode:	  inode in question
 *	@depth:	  depth of the affected branch
 *	@offsets: offsets of pointers in that branch (see mockfs_block_to_path)
 *	@chain:	  place to store the pointers to partial indirect blocks
 *	@top:	  place to the (detached) top of branch
 *
 *	This is a helper function used by mockfs_truncate().
 *
 *	When we do truncate() we may have to clean the ends of several
 *	indirect blocks but leave the blocks themselves alive. Block is
 *	partially truncated if some data below the new i_size is referred
 *	from it (and it is on the path to the first completely truncated
 *	data block, indeed).  We have to free the top of that path along
 *	with everything to the right of the path. Since no allocation
 *	past the truncation point is possible until mockfs_truncate()
 *	finishes, we may safely do the latter, but top of branch may
 *	require special attention - pageout below the truncation point
 *	might try to populate it.
 *
 *	We atomically detach the top of branch from the tree, store the
 *	block number of its root in *@top, pointers to buffer_heads of
 *	partially truncated blocks - in @chain[].bh and pointers to
 *	their last elements that should not be removed - in
 *	@chain[].p. Return value is the pointer to last filled element
 *	of @chain.
 *
 *	The work left to caller to do the actual freeing of subtrees:
 *		a) free the subtree starting from *@top
 *		b) free the subtrees whose roots are stored in
 *			(@chain[i].p+1 .. end of @chain[i].bh->b_data)
 *		c) free the subtrees growing from the inode past the @chain[0].
 *			(no partially truncated stuff there).  */

static Indirect *mockfs_find_shared(struct inode *inode, int depth,
				  mockfs_lblk_t offsets[4], Indirect chain[4],
				  __le32 *top)
{
	Indirect *partial, *p;
	int k, err;

	*top = 0;
	/* Make k index the deepest non-null offset + 1 */
	for (k = depth; k > 1 && !offsets[k-1]; k--)
		;
	partial = mockfs_get_branch(inode, k, offsets, chain, &err);
	/* Writer: pointers */
	if (!partial)
		partial = chain + k-1;
	/*
	 * If the branch acquired continuation since we've looked at it -
	 * fine, it should all survive and (new) top doesn't belong to us.
	 */
	if (!partial->key && *partial->p)
		/* Writer: end */
		goto no_top;
	for (p = partial; (p > chain) && all_zeroes((__le32 *) p->bh->b_data, p->p); p--)
		;
	/*
	 * OK, we've found the last block that must survive. The rest of our
	 * branch should be detached before unlocking. However, if that rest
	 * of branch is all ours and does not grow immediately from the inode
	 * it's easier to cheat and just decrement partial->p.
	 */
	if (p == chain + k - 1 && p > chain) {
		p->p--;
	} else {
		*top = *p->p;
		/* Nope, don't do this in mockfs.  Must leave the tree intact */
#if 0
		*p->p = 0;
#endif
	}
	/* Writer: end */

	while (partial > p) {
		brelse(partial->bh);
		partial--;
	}
no_top:
	return partial;
}

/*
 * Zero a number of block pointers in either an inode or an indirect block.
 * If we restart the transaction we must again get write access to the
 * indirect block for further modification.
 *
 * We release `count' blocks on disk, but (last - first) may be greater
 * than `count' because there can be holes in there.
 *
 * Return 0 on success, 1 on invalid block range
 * and < 0 on fatal error.
 */
static int mockfs_clear_blocks(handle_t *handle, struct inode *inode,
			     struct buffer_head *bh,
			     mockfs_fsblk_t block_to_free,
			     unsigned long count, __le32 *first,
			     __le32 *last)
{
	__le32 *p;
	int	flags = MOCKFS_FREE_BLOCKS_VALIDATED;
	int	err;

	if (S_ISDIR(inode->i_mode) || S_ISLNK(inode->i_mode))
		flags |= MOCKFS_FREE_BLOCKS_FORGET | MOCKFS_FREE_BLOCKS_METADATA;
	else if (mockfs_should_journal_data(inode))
		flags |= MOCKFS_FREE_BLOCKS_FORGET;

	if (!mockfs_data_block_valid(MOCKFS_SB(inode->i_sb), block_to_free,
				   count)) {
		MOCKFS_ERROR_INODE(inode, "attempt to clear invalid "
				 "blocks %llu len %lu",
				 (unsigned long long) block_to_free, count);
		return 1;
	}

	if (try_to_extend_transaction(handle, inode)) {
		if (bh) {
			BUFFER_TRACE(bh, "call mockfs_handle_dirty_metadata");
			err = mockfs_handle_dirty_metadata(handle, inode, bh);
			if (unlikely(err))
				goto out_err;
		}
		err = mockfs_mark_inode_dirty(handle, inode);
		if (unlikely(err))
			goto out_err;
		err = mockfs_truncate_restart_trans(handle, inode,
					mockfs_blocks_for_truncate(inode));
		if (unlikely(err))
			goto out_err;
		if (bh) {
			BUFFER_TRACE(bh, "retaking write access");
			err = mockfs_journal_get_write_access(handle, bh);
			if (unlikely(err))
				goto out_err;
		}
	}

	for (p = first; p < last; p++)
		*p = 0;

	mockfs_free_blocks(handle, inode, NULL, block_to_free, count, flags);
	return 0;
out_err:
	mockfs_std_error(inode->i_sb, err);
	return err;
}

/**
 * mockfs_free_data - free a list of data blocks
 * @handle:	handle for this transaction
 * @inode:	inode we are dealing with
 * @this_bh:	indirect buffer_head which contains *@first and *@last
 * @first:	array of block numbers
 * @last:	points immediately past the end of array
 *
 * We are freeing all blocks referred from that array (numbers are stored as
 * little-endian 32-bit) and updating @inode->i_blocks appropriately.
 *
 * We accumulate contiguous runs of blocks to free.  Conveniently, if these
 * blocks are contiguous then releasing them at one time will only affect one
 * or two bitmap blocks (+ group descriptor(s) and superblock) and we won't
 * actually use a lot of journal space.
 *
 * @this_bh will be %NULL if @first and @last point into the inode's direct
 * block pointers.
 */
static void mockfs_free_data(handle_t *handle, struct inode *inode,
			   struct buffer_head *this_bh,
			   __le32 *first, __le32 *last)
{
	mockfs_fsblk_t block_to_free = 0;    /* Starting block # of a run */
	unsigned long count = 0;	    /* Number of blocks in the run */
	__le32 *block_to_free_p = NULL;	    /* Pointer into inode/ind
					       corresponding to
					       block_to_free */
	mockfs_fsblk_t nr;		    /* Current block # */
	__le32 *p;			    /* Pointer into inode/ind
					       for current block */
	int err = 0;

	if (this_bh) {				/* For indirect block */
		BUFFER_TRACE(this_bh, "get_write_access");
		err = mockfs_journal_get_write_access(handle, this_bh);
		/* Important: if we can't update the indirect pointers
		 * to the blocks, we can't free them. */
		if (err)
			return;
	}

	for (p = first; p < last; p++) {
		nr = le32_to_cpu(*p);
		if (nr) {
			/* accumulate blocks to free if they're contiguous */
			if (count == 0) {
				block_to_free = nr;
				block_to_free_p = p;
				count = 1;
			} else if (nr == block_to_free + count) {
				count++;
			} else {
				err = mockfs_clear_blocks(handle, inode, this_bh,
						        block_to_free, count,
						        block_to_free_p, p);
				if (err)
					break;
				block_to_free = nr;
				block_to_free_p = p;
				count = 1;
			}
		}
	}

	if (!err && count > 0)
		err = mockfs_clear_blocks(handle, inode, this_bh, block_to_free,
					count, block_to_free_p, p);
	if (err < 0)
		/* fatal error */
		return;

	if (this_bh) {
		BUFFER_TRACE(this_bh, "call mockfs_handle_dirty_metadata");

		/*
		 * The buffer head should have an attached journal head at this
		 * point. However, if the data is corrupted and an indirect
		 * block pointed to itself, it would have been detached when
		 * the block was cleared. Check for this instead of OOPSing.
		 */
		if ((MOCKFS_JOURNAL(inode) == NULL) || bh2jh(this_bh))
			mockfs_handle_dirty_metadata(handle, inode, this_bh);
		else
			MOCKFS_ERROR_INODE(inode,
					 "circular indirect block detected at "
					 "block %llu",
				(unsigned long long) this_bh->b_blocknr);
	}
}

/**
 *	mockfs_free_branches - free an array of branches
 *	@handle: JBD handle for this transaction
 *	@inode:	inode we are dealing with
 *	@parent_bh: the buffer_head which contains *@first and *@last
 *	@first:	array of block numbers
 *	@last:	pointer immediately past the end of array
 *	@depth:	depth of the branches to free
 *
 *	We are freeing all blocks referred from these branches (numbers are
 *	stored as little-endian 32-bit) and updating @inode->i_blocks
 *	appropriately.
 */
static void mockfs_free_branches(handle_t *handle, struct inode *inode,
			       struct buffer_head *parent_bh,
			       __le32 *first, __le32 *last, int depth)
{
	mockfs_fsblk_t nr;
	__le32 *p;

	if (mockfs_handle_is_aborted(handle))
		return;

	if (depth--) {
		struct buffer_head *bh;
		int addr_per_block = MOCKFS_ADDR_PER_BLOCK(inode->i_sb);
		p = last;
		while (--p >= first) {
			nr = le32_to_cpu(*p);
			if (!nr)
				continue;		/* A hole */

			if (!mockfs_data_block_valid(MOCKFS_SB(inode->i_sb),
						   nr, 1)) {
				MOCKFS_ERROR_INODE(inode,
						 "invalid indirect mapped "
						 "block %lu (level %d)",
						 (unsigned long) nr, depth);
				break;
			}

			/* Go read the buffer for the next level down */
			bh = sb_bread(inode->i_sb, nr);

			/*
			 * A read failure? Report error and clear slot
			 * (should be rare).
			 */
			if (!bh) {
				MOCKFS_ERROR_INODE_BLOCK(inode, nr,
						       "Read failure");
				continue;
			}

			/* This zaps the entire block.  Bottom up. */
			BUFFER_TRACE(bh, "free child branches");
			mockfs_free_branches(handle, inode, bh,
					(__le32 *) bh->b_data,
					(__le32 *) bh->b_data + addr_per_block,
					depth);
			brelse(bh);

			/*
			 * Everything below this this pointer has been
			 * released.  Now let this top-of-subtree go.
			 *
			 * We want the freeing of this indirect block to be
			 * atomic in the journal with the updating of the
			 * bitmap block which owns it.  So make some room in
			 * the journal.
			 *
			 * We zero the parent pointer *after* freeing its
			 * pointee in the bitmaps, so if extend_transaction()
			 * for some reason fails to put the bitmap changes and
			 * the release into the same transaction, recovery
			 * will merely complain about releasing a free block,
			 * rather than leaking blocks.
			 */
			if (mockfs_handle_is_aborted(handle))
				return;
			if (try_to_extend_transaction(handle, inode)) {
				mockfs_mark_inode_dirty(handle, inode);
				mockfs_truncate_restart_trans(handle, inode,
					    mockfs_blocks_for_truncate(inode));
			}

			/*
			 * The forget flag here is critical because if
			 * we are journaling (and not doing data
			 * journaling), we have to make sure a revoke
			 * record is written to prevent the journal
			 * replay from overwriting the (former)
			 * indirect block if it gets reallocated as a
			 * data block.  This must happen in the same
			 * transaction where the data blocks are
			 * actually freed.
			 */
			mockfs_free_blocks(handle, inode, NULL, nr, 1,
					 MOCKFS_FREE_BLOCKS_METADATA|
					 MOCKFS_FREE_BLOCKS_FORGET);

			if (parent_bh) {
				/*
				 * The block which we have just freed is
				 * pointed to by an indirect block: journal it
				 */
				BUFFER_TRACE(parent_bh, "get_write_access");
				if (!mockfs_journal_get_write_access(handle,
								   parent_bh)){
					*p = 0;
					BUFFER_TRACE(parent_bh,
					"call mockfs_handle_dirty_metadata");
					mockfs_handle_dirty_metadata(handle,
								   inode,
								   parent_bh);
				}
			}
		}
	} else {
		/* We have reached the bottom of the tree. */
		BUFFER_TRACE(parent_bh, "free data blocks");
		mockfs_free_data(handle, inode, parent_bh, first, last);
	}
}

void mockfs_ind_truncate(handle_t *handle, struct inode *inode)
{
	struct mockfs_inode_info *ei = MOCKFS_I(inode);
	__le32 *i_data = ei->i_data;
	int addr_per_block = MOCKFS_ADDR_PER_BLOCK(inode->i_sb);
	mockfs_lblk_t offsets[4];
	Indirect chain[4];
	Indirect *partial;
	__le32 nr = 0;
	int n = 0;
	mockfs_lblk_t last_block, max_block;
	unsigned blocksize = inode->i_sb->s_blocksize;

	last_block = (inode->i_size + blocksize-1)
					>> MOCKFS_BLOCK_SIZE_BITS(inode->i_sb);
	max_block = (MOCKFS_SB(inode->i_sb)->s_bitmap_maxbytes + blocksize-1)
					>> MOCKFS_BLOCK_SIZE_BITS(inode->i_sb);

	if (last_block != max_block) {
		n = mockfs_block_to_path(inode, last_block, offsets, NULL);
		if (n == 0)
			return;
	}

	mockfs_es_remove_extent(inode, last_block, EXT_MAX_BLOCKS - last_block);

	/*
	 * The orphan list entry will now protect us from any crash which
	 * occurs before the truncate completes, so it is now safe to propagate
	 * the new, shorter inode size (held for now in i_size) into the
	 * on-disk inode. We do this via i_disksize, which is the value which
	 * mockfs *really* writes onto the disk inode.
	 */
	ei->i_disksize = inode->i_size;

	if (last_block == max_block) {
		/*
		 * It is unnecessary to free any data blocks if last_block is
		 * equal to the indirect block limit.
		 */
		return;
	} else if (n == 1) {		/* direct blocks */
		mockfs_free_data(handle, inode, NULL, i_data+offsets[0],
			       i_data + MOCKFS_NDIR_BLOCKS);
		goto do_indirects;
	}

	partial = mockfs_find_shared(inode, n, offsets, chain, &nr);
	/* Kill the top of shared branch (not detached) */
	if (nr) {
		if (partial == chain) {
			/* Shared branch grows from the inode */
			mockfs_free_branches(handle, inode, NULL,
					   &nr, &nr+1, (chain+n-1) - partial);
			*partial->p = 0;
			/*
			 * We mark the inode dirty prior to restart,
			 * and prior to stop.  No need for it here.
			 */
		} else {
			/* Shared branch grows from an indirect block */
			BUFFER_TRACE(partial->bh, "get_write_access");
			mockfs_free_branches(handle, inode, partial->bh,
					partial->p,
					partial->p+1, (chain+n-1) - partial);
		}
	}
	/* Clear the ends of indirect blocks on the shared branch */
	while (partial > chain) {
		mockfs_free_branches(handle, inode, partial->bh, partial->p + 1,
				   (__le32*)partial->bh->b_data+addr_per_block,
				   (chain+n-1) - partial);
		BUFFER_TRACE(partial->bh, "call brelse");
		brelse(partial->bh);
		partial--;
	}
do_indirects:
	/* Kill the remaining (whole) subtrees */
	switch (offsets[0]) {
	default:
		nr = i_data[MOCKFS_IND_BLOCK];
		if (nr) {
			mockfs_free_branches(handle, inode, NULL, &nr, &nr+1, 1);
			i_data[MOCKFS_IND_BLOCK] = 0;
		}
	case MOCKFS_IND_BLOCK:
		nr = i_data[MOCKFS_DIND_BLOCK];
		if (nr) {
			mockfs_free_branches(handle, inode, NULL, &nr, &nr+1, 2);
			i_data[MOCKFS_DIND_BLOCK] = 0;
		}
	case MOCKFS_DIND_BLOCK:
		nr = i_data[MOCKFS_TIND_BLOCK];
		if (nr) {
			mockfs_free_branches(handle, inode, NULL, &nr, &nr+1, 3);
			i_data[MOCKFS_TIND_BLOCK] = 0;
		}
	case MOCKFS_TIND_BLOCK:
		;
	}
}

/**
 *	mockfs_ind_remove_space - remove space from the range
 *	@handle: JBD handle for this transaction
 *	@inode:	inode we are dealing with
 *	@start:	First block to remove
 *	@end:	One block after the last block to remove (exclusive)
 *
 *	Free the blocks in the defined range (end is exclusive endpoint of
 *	range). This is used by mockfs_punch_hole().
 */
int mockfs_ind_remove_space(handle_t *handle, struct inode *inode,
			  mockfs_lblk_t start, mockfs_lblk_t end)
{
	struct mockfs_inode_info *ei = MOCKFS_I(inode);
	__le32 *i_data = ei->i_data;
	int addr_per_block = MOCKFS_ADDR_PER_BLOCK(inode->i_sb);
	mockfs_lblk_t offsets[4], offsets2[4];
	Indirect chain[4], chain2[4];
	Indirect *partial, *partial2;
	mockfs_lblk_t max_block;
	__le32 nr = 0, nr2 = 0;
	int n = 0, n2 = 0;
	unsigned blocksize = inode->i_sb->s_blocksize;

	max_block = (MOCKFS_SB(inode->i_sb)->s_bitmap_maxbytes + blocksize-1)
					>> MOCKFS_BLOCK_SIZE_BITS(inode->i_sb);
	if (end >= max_block)
		end = max_block;
	if ((start >= end) || (start > max_block))
		return 0;

	n = mockfs_block_to_path(inode, start, offsets, NULL);
	n2 = mockfs_block_to_path(inode, end, offsets2, NULL);

	BUG_ON(n > n2);

	if ((n == 1) && (n == n2)) {
		/* We're punching only within direct block range */
		mockfs_free_data(handle, inode, NULL, i_data + offsets[0],
			       i_data + offsets2[0]);
		return 0;
	} else if (n2 > n) {
		/*
		 * Start and end are on a different levels so we're going to
		 * free partial block at start, and partial block at end of
		 * the range. If there are some levels in between then
		 * do_indirects label will take care of that.
		 */

		if (n == 1) {
			/*
			 * Start is at the direct block level, free
			 * everything to the end of the level.
			 */
			mockfs_free_data(handle, inode, NULL, i_data + offsets[0],
				       i_data + MOCKFS_NDIR_BLOCKS);
			goto end_range;
		}


		partial = mockfs_find_shared(inode, n, offsets, chain, &nr);
		if (nr) {
			if (partial == chain) {
				/* Shared branch grows from the inode */
				mockfs_free_branches(handle, inode, NULL,
					   &nr, &nr+1, (chain+n-1) - partial);
				*partial->p = 0;
			} else {
				/* Shared branch grows from an indirect block */
				BUFFER_TRACE(partial->bh, "get_write_access");
				mockfs_free_branches(handle, inode, partial->bh,
					partial->p,
					partial->p+1, (chain+n-1) - partial);
			}
		}

		/*
		 * Clear the ends of indirect blocks on the shared branch
		 * at the start of the range
		 */
		while (partial > chain) {
			mockfs_free_branches(handle, inode, partial->bh,
				partial->p + 1,
				(__le32 *)partial->bh->b_data+addr_per_block,
				(chain+n-1) - partial);
			BUFFER_TRACE(partial->bh, "call brelse");
			brelse(partial->bh);
			partial--;
		}

end_range:
		partial2 = mockfs_find_shared(inode, n2, offsets2, chain2, &nr2);
		if (nr2) {
			if (partial2 == chain2) {
				/*
				 * Remember, end is exclusive so here we're at
				 * the start of the next level we're not going
				 * to free. Everything was covered by the start
				 * of the range.
				 */
				goto do_indirects;
			}
		} else {
			/*
			 * mockfs_find_shared returns Indirect structure which
			 * points to the last element which should not be
			 * removed by truncate. But this is end of the range
			 * in punch_hole so we need to point to the next element
			 */
			partial2->p++;
		}

		/*
		 * Clear the ends of indirect blocks on the shared branch
		 * at the end of the range
		 */
		while (partial2 > chain2) {
			mockfs_free_branches(handle, inode, partial2->bh,
					   (__le32 *)partial2->bh->b_data,
					   partial2->p,
					   (chain2+n2-1) - partial2);
			BUFFER_TRACE(partial2->bh, "call brelse");
			brelse(partial2->bh);
			partial2--;
		}
		goto do_indirects;
	}

	/* Punch happened within the same level (n == n2) */
	partial = mockfs_find_shared(inode, n, offsets, chain, &nr);
	partial2 = mockfs_find_shared(inode, n2, offsets2, chain2, &nr2);

	/* Free top, but only if partial2 isn't its subtree. */
	if (nr) {
		int level = min(partial - chain, partial2 - chain2);
		int i;
		int subtree = 1;

		for (i = 0; i <= level; i++) {
			if (offsets[i] != offsets2[i]) {
				subtree = 0;
				break;
			}
		}

		if (!subtree) {
			if (partial == chain) {
				/* Shared branch grows from the inode */
				mockfs_free_branches(handle, inode, NULL,
						   &nr, &nr+1,
						   (chain+n-1) - partial);
				*partial->p = 0;
			} else {
				/* Shared branch grows from an indirect block */
				BUFFER_TRACE(partial->bh, "get_write_access");
				mockfs_free_branches(handle, inode, partial->bh,
						   partial->p,
						   partial->p+1,
						   (chain+n-1) - partial);
			}
		}
	}

	if (!nr2) {
		/*
		 * mockfs_find_shared returns Indirect structure which
		 * points to the last element which should not be
		 * removed by truncate. But this is end of the range
		 * in punch_hole so we need to point to the next element
		 */
		partial2->p++;
	}

	while (partial > chain || partial2 > chain2) {
		int depth = (chain+n-1) - partial;
		int depth2 = (chain2+n2-1) - partial2;

		if (partial > chain && partial2 > chain2 &&
		    partial->bh->b_blocknr == partial2->bh->b_blocknr) {
			/*
			 * We've converged on the same block. Clear the range,
			 * then we're done.
			 */
			mockfs_free_branches(handle, inode, partial->bh,
					   partial->p + 1,
					   partial2->p,
					   (chain+n-1) - partial);
			BUFFER_TRACE(partial->bh, "call brelse");
			brelse(partial->bh);
			BUFFER_TRACE(partial2->bh, "call brelse");
			brelse(partial2->bh);
			return 0;
		}

		/*
		 * The start and end partial branches may not be at the same
		 * level even though the punch happened within one level. So, we
		 * give them a chance to arrive at the same level, then walk
		 * them in step with each other until we converge on the same
		 * block.
		 */
		if (partial > chain && depth <= depth2) {
			mockfs_free_branches(handle, inode, partial->bh,
					   partial->p + 1,
					   (__le32 *)partial->bh->b_data+addr_per_block,
					   (chain+n-1) - partial);
			BUFFER_TRACE(partial->bh, "call brelse");
			brelse(partial->bh);
			partial--;
		}
		if (partial2 > chain2 && depth2 <= depth) {
			mockfs_free_branches(handle, inode, partial2->bh,
					   (__le32 *)partial2->bh->b_data,
					   partial2->p,
					   (chain2+n2-1) - partial2);
			BUFFER_TRACE(partial2->bh, "call brelse");
			brelse(partial2->bh);
			partial2--;
		}
	}
	return 0;

do_indirects:
	/* Kill the remaining (whole) subtrees */
	switch (offsets[0]) {
	default:
		if (++n >= n2)
			return 0;
		nr = i_data[MOCKFS_IND_BLOCK];
		if (nr) {
			mockfs_free_branches(handle, inode, NULL, &nr, &nr+1, 1);
			i_data[MOCKFS_IND_BLOCK] = 0;
		}
	case MOCKFS_IND_BLOCK:
		if (++n >= n2)
			return 0;
		nr = i_data[MOCKFS_DIND_BLOCK];
		if (nr) {
			mockfs_free_branches(handle, inode, NULL, &nr, &nr+1, 2);
			i_data[MOCKFS_DIND_BLOCK] = 0;
		}
	case MOCKFS_DIND_BLOCK:
		if (++n >= n2)
			return 0;
		nr = i_data[MOCKFS_TIND_BLOCK];
		if (nr) {
			mockfs_free_branches(handle, inode, NULL, &nr, &nr+1, 3);
			i_data[MOCKFS_TIND_BLOCK] = 0;
		}
	case MOCKFS_TIND_BLOCK:
		;
	}
	return 0;
}
