
all:
	gcc -Wall -Wno-shift-count-overflow -O3 -DSM3_MACRO -o sm3sum sm3sum.c sm3.c
clean:
	rm -f sm3sum
