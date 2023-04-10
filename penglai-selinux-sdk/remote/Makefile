CC=riscv64-linux-gnu-gcc

HOST=remote

all:
	make -C gm
	$(CC) -o $(HOST) -static -I ../lib/include/  remote.c  ../lib/libpenglai-enclave-host.a  -lpthread

clean:
	make -C gm clean
	rm -f *.o $(HOST)
	
