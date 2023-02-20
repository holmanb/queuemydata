CFLAGS       = -fPIC -g -pedantic -Wextra
LDFLAGS      = -shared -pthread
DEBUG        = -g -D=DEBUG
LDPRELOAD = LD_PRELOAD=./libqueuemydata.so
TEST = sync; cat counters.log debug.log
BIN = libqueuemydata.so
SRC = src/queuemydata.c

.PHONY: all
all: shared-debug

.PHONY: shared-debug
shared-debug:
	gcc -o $(BIN) $(SRC) $(CFLAGS) $(LDFLAGS) $(DEBUG)

shared:
	gcc -o $(BIN) $(SRC) $(CFLAGS) $(LDFLAGS)

.PHONY: clean
clean:
	rm libqueuemydata.so counters.log debug.log

.PHONY: test
test: shared-debug
	$(LDPRELOAD) $(TEST)

.PHONY: fmt
fmt:
	clang-format-11 -i src/queuemydata.c

.PHONY: test-valgrind
test-valgrind: all
	$(LDPRELOAD) valgrind                      \
		--leak-check=full                      \
		--track-origins=yes                    \
		--exit-on-first-error=yes              \
		--show-leak-kinds=all                  \
		$(TEST)

.PHONY: test-asan
test-asan:
	clang -O1 $(CFLAGS) \
		-fsanitize=address \
		-shared-libasan \
		-fno-omit-frame-pointer \
		-fno-optimize-sibling-calls \
		$(SRC) $(LDFLAGS) -o $(BIN)
		LD_PRELOAD="/usr/lib/llvm-14/lib/clang/14.0.6/lib/linux/libclang_rt.asan-x86_64.so ./libqueuemydata.so" $(TEST)

.PHONY: test-leak
test-leak:
	clang -O1 $(CFLAGS) \
		-fsanitize=leak \
		-fno-omit-frame-pointer \
		-fno-optimize-sibling-calls \
		$(SRC) $(LDFLAGS) -o $(BIN)
	ASAN_OPTIONS=detect_leaks=1 $(LDPRELOAD) $(TEST)
