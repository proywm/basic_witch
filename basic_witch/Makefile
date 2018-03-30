EXES= test7
all: $(EXES)

test%: test%.c
	gcc -g -O2 -std=gnu99 perf_parser.c $^ -o $@

check: $(EXES)
	./test7

clean: 
	rm -f $(EXES)
