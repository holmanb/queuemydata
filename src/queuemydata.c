#define _GNU_SOURCE
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/mman.h>
#include <stdio.h>

#define PRIORITY 101

static int (*libc_fsync)(int);
static int (*libc_msync)(void *, size_t, int);
static int (*libc_sync)(void);
static int (*libc_fdatasync)(int);
static int (*libc_sync_file_range)(int fd, off64_t offset, off64_t nbytes,
				   unsigned int flags);

enum {
	FSYNC,
	MSYNC,
	SYNC,
	FDATASYNC,
	SYNC_FILE_RANGE,
};

static int counters[5];

void print_counters(void)
{
	FILE *f = fopen("./counters.log", "a");
	if (f == NULL)
		printf("failed to open file\n");
	else
		fprintf(f,
			"fsync=%d\nmsync=%d\nsync=%d\nfdatasync=%d\nsync_file_range=%d\n",
			counters[FSYNC], counters[MSYNC], counters[SYNC],
			counters[FDATASYNC], counters[SYNC_FILE_RANGE]);
}

int fsync(int fd)
{
	errno = 0;
	counters[FSYNC]++;
	return 0;
}
int msync(void *addr, size_t length, int flags)
{
	errno = 0;
	counters[MSYNC]++;
	return 0;
}
void sync(void)
{
	counters[SYNC]++;
	errno = 0;
}
int fdatasync(int fd)
{
	counters[FDATASYNC]++;
	errno = 0;
	return 0;
}
int sync_file_range(int fd, off64_t offset, off64_t nbytes, unsigned int flags)
{
	counters[SYNC_FILE_RANGE]++;
	errno = 0;
	return 0;
}

static void override_sym()
{
	libc_fsync = dlsym(RTLD_NEXT, "fsync");
	if (!libc_fsync || dlerror())
		_exit(1);

	libc_msync = dlsym(RTLD_NEXT, "msync");
	if (!libc_msync || dlerror())
		_exit(1);

	libc_sync = dlsym(RTLD_NEXT, "sync");
	if (!libc_sync || dlerror())
		_exit(1);

	libc_fdatasync = dlsym(RTLD_NEXT, "fdatasync");
	if (!libc_fdatasync || dlerror())
		_exit(1);

	libc_sync_file_range = dlsym(RTLD_NEXT, "sync_file_range");
	if (!libc_sync_file_range || dlerror())
		_exit(1);
}

__attribute__((constructor(PRIORITY))) static void queuemydata_init(void)
{
	override_sym();
}

__attribute__((destructor(PRIORITY))) static void queuemydata_cleanup(void)
{
	print_counters();
}
