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
#include <string.h>

static void debug(char *error)
{
	FILE *f = fopen("./debug.log", "a");
	if (f == NULL)
		printf("failed to open file\n");
	else
		fprintf(f, "%s\n", error);
	fclose(f);
}

static void err(char *error)
{
	debug(error);
	_exit(1);
}

#define PRIORITY 101

#define handle_error_en(en, msg)                                               \
	do {                                                                   \
		errno = en;                                                    \
		err(msg);                                                      \
		err(strerror(en));                                             \
	} while (0)

static int (*libc_fsync)(int);
static int (*libc_msync)(void *, size_t, int);
static int (*libc_sync)(void);
static int (*libc_fdatasync)(int);
static int (*libc_sync_file_range)(int fd, off64_t offset, off64_t nbytes,
				   unsigned int flags);

static pthread_mutex_t calls_mutex;
static pthread_mutex_t cond_mutex;
static pthread_cond_t cond;
static pthread_t tid;

static int counter_call[5];
static int counter_wait[5];
static int counter_error[5];

enum ops {
	FSYNC,
	MSYNC,
	SYNC,
	FDATASYNC,
	SYNC_FILE_RANGE,
};

struct call {
	enum ops op;
	union {
		/* fsync, fdatasync */
		int fd;

		/* msync */
		struct {
			void *addr;
			size_t length;
			int flags;
		} msync;

		/* sync_file_range */
		struct {
			int fd;
			unsigned int flags;
			off64_t offset;
			off64_t nbytes;
		} sfr;

		/* sync uses none */
	};
};

struct calls {
	unsigned char top;
	struct call calls[32];
};
static struct calls calls;

static void print_counters(void)
{
	FILE *f = fopen("./counters.log", "a");
	if (f == NULL)
		printf("failed to open file\n");
	else
		fprintf(f, "Call Counters:\n");
	fprintf(f,
		"fsync=%d\nmsync=%d\nsync=%d\nfdatasync=%d\nsync_file_range=%d\n",
		counter_call[FSYNC], counter_call[MSYNC], counter_call[SYNC],
		counter_call[FDATASYNC], counter_call[SYNC_FILE_RANGE]);
	fprintf(f, "Wait Counters:\n");
	fprintf(f,
		"fsync=%d\nmsync=%d\nsync=%d\nfdatasync=%d\nsync_file_range=%d\n",
		counter_wait[FSYNC], counter_wait[MSYNC], counter_wait[SYNC],
		counter_wait[FDATASYNC], counter_wait[SYNC_FILE_RANGE]);
	fprintf(f, "Error Counters:\n");
	fprintf(f,
		"fsync=%d\nmsync=%d\nsync=%d\nfdatasync=%d\nsync_file_range=%d\n",
		counter_error[FSYNC], counter_error[MSYNC], counter_error[SYNC],
		counter_error[FDATASYNC], counter_error[SYNC_FILE_RANGE]);
}

static int async_ops(struct call *c)
{
	switch (c->op) {
	case FSYNC:
		return libc_fsync(c->fd);
	case MSYNC:
		return libc_msync(c->msync.addr, c->msync.length,
				  c->msync.flags);
	case SYNC:
		return libc_sync();
	case FDATASYNC:
		return libc_fdatasync(c->fd);
	case SYNC_FILE_RANGE:
		return libc_sync_file_range(c->sfr.fd, c->sfr.offset,
					    c->sfr.nbytes, c->sfr.flags);
	default:
		err("Invalid op");
	}
}

static void override_sym()
{
	libc_fsync = dlsym(RTLD_NEXT, "fsync");
	if (!libc_fsync || dlerror())
		err("dlsym error");

	libc_msync = dlsym(RTLD_NEXT, "msync");
	if (!libc_msync || dlerror())
		err("dlsym error");

	libc_sync = dlsym(RTLD_NEXT, "sync");
	if (!libc_sync || dlerror())
		err("dlsym error");

	libc_fdatasync = dlsym(RTLD_NEXT, "fdatasync");
	if (!libc_fdatasync || dlerror())
		err("dlsym error");

	libc_sync_file_range = dlsym(RTLD_NEXT, "sync_file_range");
	if (!libc_sync_file_range || dlerror())
		err("dlsym error");
}

static int put_call(struct call *c)
{
	int e;
	if ((e = pthread_mutex_lock(&calls_mutex)) != 0)
		handle_error_en(e, "failed to unlock mutex");
	if (calls.top == 32)
		return 1;
	calls.top++;

	memcpy(&calls.calls[calls.top], c, sizeof(struct call));

	if ((e = pthread_mutex_unlock(&calls_mutex)) != 0)
		handle_error_en(e, "failed to unlock mutex");
	if ((e = pthread_cond_signal(&cond)) != 0)
		handle_error_en(e, "failed to signal condition");
	return 0;
}

static int get_call(struct call *c)
{
	int e;
	if ((e = pthread_mutex_lock(&calls_mutex)) != 0)
		handle_error_en(e, "failed to unlock mutex");

	if (calls.top == 0)
		return 1;

	memcpy(c, &calls.calls[calls.top], sizeof(struct call));

	calls.top--;
	if ((e = pthread_mutex_unlock(&calls_mutex)) != 0)
		handle_error_en(e, "failed to unlock mutex");
	return 0;
}

int fsync(int fd)
{
	int e;
	struct call c = { .fd = fd };
	while ((e = put_call(&c)) != 0)
		counter_wait[FSYNC]++;
	errno = 0;
	counter_call[FSYNC]++;
	return 0;
}
int msync(void *addr, size_t length, int flags)
{
	int e;
	struct call c = (struct call){
		.msync = { .addr = addr, .length = length, .flags = flags }
	};
	while ((e = put_call(&c)) != 0)
		counter_wait[MSYNC]++;
	errno = 0;
	counter_call[MSYNC]++;
	return 0;
}
void sync(void)
{
	int e;
	struct call c = { 0 };
	while ((e = put_call(&c)) != 0)
		counter_wait[SYNC]++;
	counter_call[SYNC]++;
	errno = 0;
}
int fdatasync(int fd)
{
	int e;
	struct call c = { .fd = fd };
	while ((e = put_call(&c)) != 0)
		counter_wait[FDATASYNC]++;
	counter_call[FDATASYNC]++;
	errno = 0;
	return 0;
}
int sync_file_range(int fd, off64_t offset, off64_t nbytes, unsigned int flags)
{
	int e;
	struct call c = (struct call){ .sfr = {
					       .fd = fd,
					       .offset = offset,
					       .nbytes = nbytes,
					       .flags = flags,
				       } };
	while ((e = put_call(&c)) != 0)
		counter_wait[SYNC_FILE_RANGE]++;
	counter_call[SYNC_FILE_RANGE]++;
	errno = 0;
	return 0;
}

static void init_calls()
{
	int e;
	if ((e = pthread_mutex_init(&calls_mutex, NULL)) != 0)
		handle_error_en(e, "failed to init mutex");

	if ((e = pthread_mutex_init(&cond_mutex, NULL)) != 0)
		handle_error_en(e, "failed to init mutex");

	if ((e = pthread_cond_init(&cond, NULL)) != 0)
		handle_error_en(e, "failed to init cond");
}

static void clean_calls()
{
	int e;
	if ((e = pthread_mutex_destroy(&calls_mutex)) != 0)
		handle_error_en(e, "failed to destroy mutex");

	if ((e = pthread_mutex_destroy(&cond_mutex)) != 0)
		handle_error_en(e, "failed to destroy mutex");

	if ((e = pthread_cond_destroy(&cond)) != 0)
		handle_error_en(e, "failed to destroy cond");
}

static void *thread_loop(void *arg)
{
	int e;
	struct call call;
	if ((e = pthread_mutex_lock(&cond_mutex)) != 0)
		handle_error_en(e, "failed to lock mutex");
	while (1) {
		if ((e = pthread_cond_wait(&cond, &cond_mutex)) != 0)
			handle_error_en(e, "timedwait error");
		debug("after cond_wait");

		/* returns 1 when empty */
		while (get_call(&call) == 0) {
			/* track errors  */
			if ((e = async_ops(&call)) != 0) {
				counter_error[call.op]++;
			}
		}
		debug("after async_ops");
	}
	debug("thread loop exited");
	return NULL;
}

static void create_thread()
{
	int e;
	init_calls();

	if ((e = pthread_create(&tid, NULL, thread_loop, NULL)) != 0)
		handle_error_en(e, "thread create error");
}

static void destroy_thread()
{
	int e;
	if ((e = pthread_join(tid, NULL)) != 0)
		handle_error_en(e, "thread destroy error");
}

__attribute__((constructor(PRIORITY))) static void queuemydata_init(void)
{
	override_sym();
	create_thread();
}

__attribute__((destructor(PRIORITY))) static void queuemydata_cleanup(void)
{
	print_counters();
	//destroy_thread();
	//	clean_calls();
}
