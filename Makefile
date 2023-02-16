CFLAGS       = -fPIC -g -pedantic -Wall -Wextra
LDFLAGS      = -shared

.PHONY: all
all: shared

.PHONY: shared
shared:
	gcc -o libqueuemydata.so src/queuemydata.c -shared

.PHONY: clean
clean:
	rm libqueuemydata.so counters.log

.PHONY: test
test: shared
	LD_PRELOAD=./libqueuemydata.so sync && cat counters.log

.PHONY: fmt
fmt:
	clang-format-11 -i src/queuemydata.c
