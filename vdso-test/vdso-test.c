#include <err.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/mman.h>


unsigned long get_vdso_addr(void)
{
	char        buf[256];
	FILE       *rd;
	long long   start_addr;

	/* Get this process' memory layout */
	if (!(rd = fopen("/proc/self/maps", "r"))) {
		perror("Error: fopen() - /proc/self/maps");
		abort();
	}

	/* Find the line in /proc/self/maps that contains
	   the substring [vdso] * */
	while (fgets(buf, sizeof(buf), rd)) {
		if (strstr(buf, "[vdso]"))
			break;
	}

	fclose(rd);

	/* Locate the end memory range for [vdso] */
	//end_addr = strtoll((strchr(buf, '-') + 1), NULL, 16);

	/* Terminate the string so we can get the start
	   address really easily * */
	*(strchr(buf, '-')) = '\0';
	start_addr = strtoll(buf, NULL, 16);

	return start_addr;
}

int main(void)
{
	unsigned long vdso_addr;
	struct timeval tv;
	int fd, flags;
	void *p;

	vdso_addr = get_vdso_addr();
	printf("[%016lx]\n", vdso_addr);

	fd = open("./vdso-backdoored", O_RDONLY);
	if (fd == -1)
		err(1, "open");

	if (munmap((void *)vdso_addr, 0x2000) != 0)
		err(1, "munmap");

	flags = MAP_PRIVATE|MAP_FIXED;
	p = mmap((void *)vdso_addr, 0x2000, PROT_READ|PROT_EXEC, flags, fd, 0);
	if (p == MAP_FAILED)
		err(EXIT_FAILURE, "mmap");

	printf("[%016lx]\n", *(unsigned long *)(vdso_addr + 0xca0));

	printf("[%d]\n", gettimeofday(&tv, NULL));

	return 0;
}
