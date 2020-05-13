/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB
*/

#include "fuse_lowlevel.h"
#include "fuse_kernel.h"
#include "fuse_i.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <assert.h>

static int fuse_kern_chan_receive(struct fuse_chan **chp, char *buf,
				  size_t size)
{
	struct fuse_chan *ch = *chp;
	int err;
	ssize_t res;
	struct fuse_session *se = fuse_chan_session(ch);
	assert(se != NULL);

restart:
	res = read(fuse_chan_fd(ch), buf, size);
	err = errno;

	if (fuse_session_exited(se))
		return 0;
	if (res == -1) {
		/* ENOENT means the operation was interrupted, it's safe
		   to restart */
		if (err == ENOENT)
			goto restart;

		if (err == ENODEV) {
			fuse_session_exit(se);
			return 0;
		}
		/* Errors occurring during normal operation: EINTR (read
		   interrupted), EAGAIN (nonblocking I/O), ENODEV (filesystem
		   umounted) */
		if (err != EINTR && err != EAGAIN)
			perror("fuse: reading device");
		return -err;
	}
	if ((size_t) res < sizeof(struct fuse_in_header)) {
		fprintf(stderr, "short read on fuse device\n");
		return -EIO;
	}
	return res;
}

struct req_info {
	uint32_t opcode;
	char *path;
	size_t size;
	off_t off;
	int res;
};

extern pthread_key_t req_key;

extern pid_t gettid(void);

static int fuse_kern_chan_send(struct fuse_chan *ch, const struct iovec iov[],
			       size_t count)
{
	if (iov) {
		/* This is the last step before FUSE write data to kernel */
		struct req_info *info = (struct req_info *)pthread_getspecific(req_key);
		if (info->opcode == FUSE_READ) {
			/* then iov[1] stores the data that user daemon will write to kernel */
			if (info->res != iov[1].iov_len) {
				fprintf(stderr, "libfuse (chan): length not equal (%d != %lu)\n", info->res, iov[1].iov_len);
			}
			const uint8_t* p = (uint8_t *)iov[1].iov_base;
			if (info->off == 0 && iov[1].iov_len >= 8) {
				int i;
				int all_zero = 1;
				for (i=0; i < 8; i++) {
					if (*(p++) != 0x00) {
						all_zero = 0;
						break;
					}
				}
				pid_t pid = getpid();
				pid_t tid = gettid();
				fprintf(stderr, "pid=%d, tid=%d; ", pid, tid);
				p = (uint8_t *)iov[1].iov_base;
				if (all_zero) {
					fprintf(stderr, "libfuse: read all zeros on file %s, offset=%ld, size=%lu, nread=%d; ",
						info->path, info->off, info->size, info->res);
				} else {
					fprintf(stderr, "libfuse: file %s, offset=%ld, size=%lu, nread=%d; ",
						info->path, info->off, info->size, info->res);
				}
				fprintf(stderr, "first 8 bytes = 0x%.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x; ",
					(uint32_t)p[0], (uint32_t)p[1], (uint32_t)p[2], (uint32_t)p[3],
					(uint32_t)p[4], (uint32_t)p[5], (uint32_t)p[6], (uint32_t)p[7]);
				if (iov[1].iov_len >= 12) {
					fprintf(stderr, "next 4 bytes = 0x%.2x %.2x %.2x %.2x",
					(uint32_t)p[8], (uint32_t)p[9], (uint32_t)p[10], (uint32_t)p[11]);
				}
				fprintf(stderr, "\n");
			}
			free(info->path);
		}

		ssize_t res = writev(fuse_chan_fd(ch), iov, count);
		int err = errno;

		if (res == -1) {
			struct fuse_session *se = fuse_chan_session(ch);

			assert(se != NULL);

			/* ENOENT means the operation was interrupted */
			if (!fuse_session_exited(se) && err != ENOENT)
				perror("fuse: writing device");
			return -err;
		}
	}
	return 0;
}

static void fuse_kern_chan_destroy(struct fuse_chan *ch)
{
	int fd = fuse_chan_fd(ch);

	if (fd != -1)
		close(fd);
}

#define MIN_BUFSIZE 0x21000

struct fuse_chan *fuse_kern_chan_new(int fd)
{
	struct fuse_chan_ops op = {
		.receive = fuse_kern_chan_receive,
		.send = fuse_kern_chan_send,
		.destroy = fuse_kern_chan_destroy,
	};
	size_t bufsize = getpagesize() + 0x1000;
	bufsize = bufsize < MIN_BUFSIZE ? MIN_BUFSIZE : bufsize;
	return fuse_chan_new(&op, fd, bufsize, NULL);
}
