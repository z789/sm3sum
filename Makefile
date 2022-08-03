CC=gcc
STD=gnu99
all:
	$(CC) -Wall -std=$(STD) -Wno-shift-count-overflow -O2 -DSM3_MACRO -o sm3sum sm3sum.c sm3.c

perf:
	$(CC) -Wall -std=$(STD) -O2 -DSM3_MACRO -Wno-shift-count-overflow -o sm3test_macro2 sm3test.c sm3.c
	$(CC) -Wall -std=$(STD) -O3 -DSM3_MACRO -Wno-shift-count-overflow -o sm3test_macro3 sm3test.c sm3.c
	$(CC) -Wall -std=$(STD) -O2 -o sm3test2 sm3test.c sm3.c
	$(CC) -Wall -std=$(STD) -O3 -o sm3test3 sm3test.c sm3.c
	$(CC) -Wall -std=$(STD) -o sm3test sm3test.c sm3.c
	$(CC) -Wall -std=$(STD) -Og -o sm3testg sm3test.c sm3.c
	./sm3test2 4096 1024000
	./sm3test3 4096 1024000
	./sm3test_macro2 4096 1024000
	./sm3test_macro3 4096 1024000
	./sm3test 4096 1024000
	./sm3testg 4096 1024000
clean:
	rm -f sm3sum sm3test2 sm3test3 sm3test_macro2 sm3test_macro3 sm3test sm3testg
