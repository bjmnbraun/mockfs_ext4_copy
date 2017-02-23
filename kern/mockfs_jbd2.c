/*
 * Interface between mockfs and JBD
 */

#include "mockfs_jbd2.h"


/* Just increment the non-pointer handle value */
static handle_t *mockfs_get_nojournal(void)
{
	handle_t *handle = current->journal_info;
	unsigned long ref_cnt = (unsigned long)handle;

	BUG_ON(ref_cnt >= MOCKFS_NOJOURNAL_MAX_REF_COUNT);

	ref_cnt++;
	handle = (handle_t *)ref_cnt;

	current->journal_info = handle;
	return handle;
}


/* Decrement the non-pointer handle value */
static void mockfs_put_nojournal(handle_t *handle)
{
	unsigned long ref_cnt = (unsigned long)handle;

	BUG_ON(ref_cnt == 0);

	ref_cnt--;
	handle = (handle_t *)ref_cnt;

	current->journal_info = handle;
}

/*
 * Wrappers for jbd2_journal_start/end.
 */
static int mockfs_journal_check_start(struct super_block *sb)
{
	journal_t *journal;

	might_sleep();
	if (sb->s_flags & MS_RDONLY)
		return -EROFS;
	WARN_ON(sb->s_writers.frozen == SB_FREEZE_COMPLETE);
	journal = MOCKFS_SB(sb)->s_journal;
	/*
	 * Special case here: if the journal has aborted behind our
	 * backs (eg. EIO in the commit thread), then we still need to
	 * take the FS itself readonly cleanly.
	 */
	if (journal && is_journal_aborted(journal)) {
		mockfs_abort(sb, "Detected aborted journal");
		return -EROFS;
	}
	return 0;
}

handle_t *__mockfs_journal_start_sb(struct super_block *sb, unsigned int line,
				  int type, int blocks, int rsv_blocks)
{
	journal_t *journal;
	int err;

	err = mockfs_journal_check_start(sb);
	if (err < 0)
		return ERR_PTR(err);

	journal = MOCKFS_SB(sb)->s_journal;
	if (!journal)
		return mockfs_get_nojournal();
	return jbd2__journal_start(journal, blocks, rsv_blocks, GFP_NOFS,
				   type, line);
}

int __mockfs_journal_stop(const char *where, unsigned int line, handle_t *handle)
{
	struct super_block *sb;
	int err;
	int rc;

	if (!mockfs_handle_valid(handle)) {
		mockfs_put_nojournal(handle);
		return 0;
	}

	err = handle->h_err;
	if (!handle->h_transaction) {
		rc = jbd2_journal_stop(handle);
		return err ? err : rc;
	}

	sb = handle->h_transaction->t_journal->j_private;
	rc = jbd2_journal_stop(handle);

	if (!err)
		err = rc;
	if (err)
		__mockfs_std_error(sb, where, line, err);
	return err;
}

handle_t *__mockfs_journal_start_reserved(handle_t *handle, unsigned int line,
					int type)
{
	struct super_block *sb;
	int err;

	if (!mockfs_handle_valid(handle))
		return mockfs_get_nojournal();

	sb = handle->h_journal->j_private;
	err = mockfs_journal_check_start(sb);
	if (err < 0) {
		jbd2_journal_free_reserved(handle);
		return ERR_PTR(err);
	}

	err = jbd2_journal_start_reserved(handle, type, line);
	if (err < 0)
		return ERR_PTR(err);
	return handle;
}

static void mockfs_journal_abort_handle(const char *caller, unsigned int line,
				      const char *err_fn,
				      struct buffer_head *bh,
				      handle_t *handle, int err)
{
	char nbuf[16];
	const char *errstr = mockfs_decode_error(NULL, err, nbuf);

	BUG_ON(!mockfs_handle_valid(handle));

	if (bh)
		BUFFER_TRACE(bh, "abort");

	if (!handle->h_err)
		handle->h_err = err;

	if (is_handle_aborted(handle))
		return;

	printk(KERN_ERR "MOCKFS-fs: %s:%d: aborting transaction: %s in %s\n",
	       caller, line, errstr, err_fn);

	jbd2_journal_abort_handle(handle);
}

int __mockfs_journal_get_write_access(const char *where, unsigned int line,
				    handle_t *handle, struct buffer_head *bh)
{
	int err = 0;

	might_sleep();

	if (mockfs_handle_valid(handle)) {
		err = jbd2_journal_get_write_access(handle, bh);
		if (err)
			mockfs_journal_abort_handle(where, line, __func__, bh,
						  handle, err);
	}
	return err;
}

/*
 * The mockfs forget function must perform a revoke if we are freeing data
 * which has been journaled.  Metadata (eg. indirect blocks) must be
 * revoked in all cases.
 *
 * "bh" may be NULL: a metadata block may have been freed from memory
 * but there may still be a record of it in the journal, and that record
 * still needs to be revoked.
 *
 * If the handle isn't valid we're not journaling, but we still need to
 * call into mockfs_journal_revoke() to put the buffer head.
 */
int __mockfs_forget(const char *where, unsigned int line, handle_t *handle,
		  int is_metadata, struct inode *inode,
		  struct buffer_head *bh, mockfs_fsblk_t blocknr)
{
	int err;

	might_sleep();

	BUFFER_TRACE(bh, "enter");

	jbd_debug(4, "forgetting bh %p: is_metadata = %d, mode %o, "
		  "data mode %x\n",
		  bh, is_metadata, inode->i_mode,
		  test_opt(inode->i_sb, DATA_FLAGS));

	/* In the no journal case, we can just do a bforget and return */
	if (!mockfs_handle_valid(handle)) {
		bforget(bh);
		return 0;
	}

	/* Never use the revoke function if we are doing full data
	 * journaling: there is no need to, and a V1 superblock won't
	 * support it.  Otherwise, only skip the revoke on un-journaled
	 * data blocks. */

	if (test_opt(inode->i_sb, DATA_FLAGS) == MOCKFS_MOUNT_JOURNAL_DATA ||
	    (!is_metadata && !mockfs_should_journal_data(inode))) {
		if (bh) {
			BUFFER_TRACE(bh, "call jbd2_journal_forget");
			err = jbd2_journal_forget(handle, bh);
			if (err)
				mockfs_journal_abort_handle(where, line, __func__,
							  bh, handle, err);
			return err;
		}
		return 0;
	}

	/*
	 * data!=journal && (is_metadata || should_journal_data(inode))
	 */
	BUFFER_TRACE(bh, "call jbd2_journal_revoke");
	err = jbd2_journal_revoke(handle, blocknr, bh);
	if (err) {
		mockfs_journal_abort_handle(where, line, __func__,
					  bh, handle, err);
		__mockfs_abort(inode->i_sb, where, line,
			   "error %d when attempting revoke", err);
	}
	BUFFER_TRACE(bh, "exit");
	return err;
}

int __mockfs_journal_get_create_access(const char *where, unsigned int line,
				handle_t *handle, struct buffer_head *bh)
{
	int err = 0;

	if (mockfs_handle_valid(handle)) {
		err = jbd2_journal_get_create_access(handle, bh);
		if (err)
			mockfs_journal_abort_handle(where, line, __func__,
						  bh, handle, err);
	}
	return err;
}

int __mockfs_handle_dirty_metadata(const char *where, unsigned int line,
				 handle_t *handle, struct inode *inode,
				 struct buffer_head *bh)
{
	int err = 0;

	might_sleep();

	set_buffer_meta(bh);
	set_buffer_prio(bh);
	if (mockfs_handle_valid(handle)) {
		err = jbd2_journal_dirty_metadata(handle, bh);
		/* Errors can only happen due to aborted journal or a nasty bug */
		if (!is_handle_aborted(handle) && WARN_ON_ONCE(err)) {
			mockfs_journal_abort_handle(where, line, __func__, bh,
						  handle, err);
			if (inode == NULL) {
				pr_err("MOCKFS: jbd2_journal_dirty_metadata "
				       "failed: handle type %u started at "
				       "line %u, credits %u/%u, errcode %d",
				       handle->h_type,
				       handle->h_line_no,
				       handle->h_requested_credits,
				       handle->h_buffer_credits, err);
				return err;
			}
			mockfs_error_inode(inode, where, line,
					 bh->b_blocknr,
					 "journal_dirty_metadata failed: "
					 "handle type %u started at line %u, "
					 "credits %u/%u, errcode %d",
					 handle->h_type,
					 handle->h_line_no,
					 handle->h_requested_credits,
					 handle->h_buffer_credits, err);
		}
	} else {
		if (inode)
			mark_buffer_dirty_inode(bh, inode);
		else
			mark_buffer_dirty(bh);
		if (inode && inode_needs_sync(inode)) {
			sync_dirty_buffer(bh);
			if (buffer_req(bh) && !buffer_uptodate(bh)) {
				struct mockfs_super_block *es;

				es = MOCKFS_SB(inode->i_sb)->s_es;
				es->s_last_error_block =
					cpu_to_le64(bh->b_blocknr);
				mockfs_error_inode(inode, where, line,
						 bh->b_blocknr,
					"IO error syncing itable block");
				err = -EIO;
			}
		}
	}
	return err;
}

int __mockfs_handle_dirty_super(const char *where, unsigned int line,
			      handle_t *handle, struct super_block *sb)
{
	struct buffer_head *bh = MOCKFS_SB(sb)->s_sbh;
	int err = 0;

	mockfs_superblock_csum_set(sb);
	if (mockfs_handle_valid(handle)) {
		err = jbd2_journal_dirty_metadata(handle, bh);
		if (err)
			mockfs_journal_abort_handle(where, line, __func__,
						  bh, handle, err);
	} else
		mark_buffer_dirty(bh);
	return err;
}
