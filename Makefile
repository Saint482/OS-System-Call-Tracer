CC     = gcc
CFLAGS = -Wall -Wextra -O2
TESTS  = tests/test_io tests/test_fork tests/test_cpu tests/test_suspicious

all: tracer $(TESTS)

tracer: tracer.c
	$(CC) $(CFLAGS) $< -o $@

tests/%: tests/%.c
	$(CC) -O0 -Wall $< -o $@

clean:
	rm -f tracer $(TESTS) tests/test.txt
