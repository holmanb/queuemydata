/*
* TODO:
* - when mutex fails, set errno and return appropriate return codes
* - behave as a lib - never call exit(), unless in debug mode
* - replace stack with fifo queue
* - tests
*
*
* Differences from eatmydata:
* - sync ops get queued and executed asynchronously
* - files open opened with synchronous flags are respected
*
*/

#define _GNU_SOURCE
#include <stdlib.h>
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
#include <stdbool.h>

#define PRIORITY 101

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

#ifdef DEBUG
#include <execinfo.h>

#define inc(counter, op) counter[op]++
#define inc_call(op) inc(counter_call, op)
#define inc_wait(op) inc(counter_wait, op)
#define inc_error(op) inc(counter_error, op)

static int counter_call[5];
static int counter_wait[5];
static int counter_error[5];

static void debug(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	FILE *f = fopen("./debug.log", "a");
	if (f == NULL)
		printf("failed to open file\n");
	else
		fprintf(f, fmt, args);
	fclose(f);
	va_end(args);
}

static void err(char *error)
{
	debug(error);
	_exit(1);
}

static void print_counters(void)
{
	FILE *f = fopen("./counters.log", "a");
	if (f != NULL) {
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
	fclose(f);
	}
	else
		printf("failed to open debug file\n");
}

static void call_print(struct call *c)
{
	switch (c->op) {
	case FSYNC:
		debug("fsync: fd=%d\n", c->fd);
		break;
	case MSYNC:
		debug("msync: addr=%p length=%zu flags=%d\n", c->msync.addr,
		      c->msync.length, c->msync.flags);
		break;
	case SYNC:
		debug("sync: no args");
		break;
	case FDATASYNC:
		debug("sync: fd=%d\n", c->fd);
		break;
	case SYNC_FILE_RANGE:
		debug("sync_file_range: fd=%p flags=%du offset=%jd nbytes=%jd\n",
		      c->sfr.fd, c->sfr.flags, c->sfr.offset, c->sfr.offset,
		      c->sfr.nbytes);
		break;
	default:
		err("Invalid op");
	}
}

static void handle_error_en(int en, char *msg)
{
	errno = en;
	debug(msg);
	debug(strerror(en));
}
#else
#define inc(counter, op) do {}while(0)
#define inc_call(op) do {}while(0)
#define inc_wait(op) do {}while(0)
#define inc_error(op) do {}while(0)
#define print_counters() do {}while(0)
#define debug(msg) do {}while(0)
#define err(msg) do {}while(0)
#define handle_error_en(en, msg)
#endif

static int (*libc_fsync)(int);
static int (*libc_msync)(void *, size_t, int);
static int (*libc_sync)(void);
static int (*libc_fdatasync)(int);
static int (*libc_sync_file_range)(int fd, off64_t offset, off64_t nbytes,
				   unsigned int flags);


static bool cleanup = false;
static bool queuemydata_enabled = false;
unsigned char top;
struct call calls[32];
static pthread_mutex_t calls_mutex;
static pthread_mutex_t cond_mutex;
static pthread_cond_t cond;
static pthread_t tid;


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
	libc_fsync = (int (*)(int))(intptr_t)dlsym(RTLD_NEXT, "fsync");
	if (!libc_fsync || dlerror())
		goto dlsym_error;

	libc_msync = (int (*)(void *, size_t,  int))(intptr_t)dlsym(RTLD_NEXT, "msync");
	if (!libc_msync || dlerror())
		goto dlsym_error;

	libc_sync = (int (*)(void))(intptr_t)dlsym(RTLD_NEXT, "sync");
	if (!libc_sync || dlerror())
		goto dlsym_error;

	libc_fdatasync = (int (*)(int))(intptr_t)dlsym(RTLD_NEXT, "fdatasync");
	if (!libc_fdatasync || dlerror())
		goto dlsym_error;

	libc_sync_file_range = (int (*)(int,  off64_t,  off64_t,  unsigned int))(intptr_t)dlsym(RTLD_NEXT, "sync_file_range");
	if (!libc_sync_file_range || dlerror())
		goto dlsym_error;

	queuemydata_enabled = true;
	return;
dlsym_error:
	err("dlsym error");
}

static int put_call(struct call *c)
{
	int e;
	if ((e = pthread_mutex_lock(&calls_mutex)) != 0)
		handle_error_en(e, "failed to lock call mutex");
	if (top == 32) {
		if ((e = pthread_mutex_unlock(&calls_mutex)) != 0)
			handle_error_en(e, "failed to unlock mutex");
		return 1;
	}
	memcpy(&calls[top], c, sizeof(struct call));
	top++;

	if ((e = pthread_mutex_unlock(&calls_mutex)) != 0)
		handle_error_en(e, "failed to unlock mutex");

	/* signal / wait must happen under mutex */
	if ((e = pthread_mutex_lock(&cond_mutex)) != 0)
		handle_error_en(e, "failed to lock cond mutex");
	if ((e = pthread_cond_signal(&cond)) != 0)
		handle_error_en(e, "failed to signal condition");
	if ((e = pthread_mutex_unlock(&cond_mutex)) != 0)
		handle_error_en(e, "failed to unlock mutex");
	return 0;
}

static int get_call(struct call *c)
{
	int e;
	if ((e = pthread_mutex_lock(&calls_mutex)) != 0)
		handle_error_en(e, "failed to lock call mutex");

	if (top == 0) {
		if ((e = pthread_mutex_unlock(&calls_mutex)) != 0)
			handle_error_en(e, "failed to unlock mutex");
		return 1;
	}

	top--;
	memcpy(c, &calls[top], sizeof(struct call));

	if ((e = pthread_mutex_unlock(&calls_mutex)) != 0)
		handle_error_en(e, "failed to unlock mutex");
	return 0;
}

int fsync(int fd)
{
	int e;
	struct call c = { .op = FSYNC, .fd = fd };
	inc_call(FSYNC);
	while ((e = put_call(&c)) != 0)
		inc_wait(FSYNC);
	errno = 0;
	return 0;
}
int msync(void *addr, size_t length, int flags)
{
	int e;
	struct call c = {
		.op = MSYNC,
		.msync = { .addr = addr, .length = length, .flags = flags }
	};
	inc_call(MSYNC);
	while ((e = put_call(&c)) != 0)
		inc_wait(MSYNC);
	errno = 0;
	return 0;
}
void sync(void)
{
	int e;
	struct call c = { .op = SYNC };
	inc_call(SYNC);
	while ((e = put_call(&c)) != 0)
		inc_wait(SYNC);
	errno = 0;
}
int fdatasync(int fd)
{
	int e;
	struct call c = { .op = FDATASYNC, .fd = fd };
	inc_call(FDATASYNC);
	while ((e = put_call(&c)) != 0)
		inc_wait(FDATASYNC);
	errno = 0;
	return 0;
}
int sync_file_range(int fd, off64_t offset, off64_t nbytes, unsigned int flags)
{
	int e;
	struct call c = { .op = SYNC_FILE_RANGE,
			  .sfr = {
				  .fd = fd,
				  .offset = offset,
				  .nbytes = nbytes,
				  .flags = flags,
			  } };
	inc_call(SYNC_FILE_RANGE);
	while ((e = put_call(&c)) != 0)
		inc_wait(SYNC_FILE_RANGE);
	errno = 0;
	return 0;
}

static void *thread_loop(void *arg)
{
	int e;
	struct call call = { 0 };
	/* signal / wait must happen under mutex */
	if ((e = pthread_mutex_lock(&cond_mutex)) != 0)
		handle_error_en(e, "failed to lock cond mutex");
	while (!cleanup) {
		if ((e = pthread_cond_wait(&cond, &cond_mutex)) != 0)
			handle_error_en(e, "timedwait error");

		/* signals received when not waiting are ignored */
		while (get_call(&call) == 0) {
			if ((e = async_ops(&call)) != 0) {
				inc_error(call.op);
			}
		}
	}
	if ((e = pthread_mutex_unlock(&cond_mutex)) != 0)
		handle_error_en(e, "failed to unlock mutex");
	return NULL;
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

	if ((e = pthread_create(&tid, NULL, thread_loop, NULL)) != 0)
		handle_error_en(e, "thread create error");
}

static void clean_calls()
{
	int e;
	if ((e = pthread_join(tid, NULL)) != 0)
		handle_error_en(e, "thread join error");

	if ((e = pthread_mutex_destroy(&calls_mutex)) != 0)
		handle_error_en(e, "failed to destroy calls mutex");

	if ((e = pthread_mutex_destroy(&cond_mutex)) != 0)
		handle_error_en(e, "failed to destroy cond mutex");

	if ((e = pthread_cond_destroy(&cond)) != 0)
		handle_error_en(e, "failed to destroy cond");

}

__attribute__((constructor(PRIORITY))) static void queuemydata_init(void)
{
	int e;
	override_sym();
	if (queuemydata_enabled) {
		init_calls();
	}
}

__attribute__((destructor(PRIORITY))) static void queuemydata_cleanup(void)
{
	int e;
	cleanup = true;
	if (queuemydata_enabled) {
		/* send signal to thread, then join thread */
		if ((e = pthread_mutex_lock(&calls_mutex)) != 0)
			handle_error_en(e, "failed to lock mutex");
		if ((e = pthread_cond_signal(&cond)) != 0)
			handle_error_en(e, "failed to signal condition");
		if ((e = pthread_mutex_unlock(&calls_mutex)) != 0)
			handle_error_en(e, "failed to unlock mutex");
		clean_calls();
		print_counters();
	}
}
