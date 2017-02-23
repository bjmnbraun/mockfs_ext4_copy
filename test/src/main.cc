#include <sys/ioctl.h>
#include <sys/stat.h>
#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <cstdio>
#include <sys/mman.h>
#include <linux/sched.h>
#include <sched.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <stdint.h>

#define PGSIZE 4096

void test_mmap_create(char* fname){
        //size_t fsize = PGSIZE*(1<<20ULL);
        size_t fsize = 1<<20ULL;
        int fhandle = open(fname, O_RDWR | O_TRUNC | O_CREAT, 0600);
        int rc = 0;
        char* ptr;
        int mapflags = MAP_SHARED;

        assert(fhandle >= 0);
        printf("Calling truncate...\n");
        rc = ftruncate(fhandle, fsize);
        assert(rc == 0);
        printf("Calling mmap...\n");
        ptr = (char*)mmap(
                NULL,
                fsize,
                PROT_READ | PROT_WRITE,
                mapflags,
                fhandle,
                0
        );
        assert(ptr != MAP_FAILED);
        printf(
                "Create-1 %d %d %d\n",
                ptr[PGSIZE*1],
                ptr[PGSIZE*2],
                ptr[PGSIZE*3]
        );

        ptr[PGSIZE*2] = 42;

        printf(
                "Create-2 %d %d %d %d\n",
                ptr[PGSIZE*1],
                ptr[PGSIZE*2],
                ptr[PGSIZE*3],
                ptr[PGSIZE*4]
        );


munmap:
        munmap(ptr, fsize);
close:
        close(fhandle);
}

int main(int argc, char** argv){
        assert(argc >= 2);
        test_mmap_create(argv[1]);
        printf("Main exited successfully!\n");
}
