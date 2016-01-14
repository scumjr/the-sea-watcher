#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/io.h>

#define PORT_SMI_CMD             0x00b2

int main(void)
{
    if (ioperm(PORT_SMI_CMD, 1, 1) != 0)
        err(EXIT_FAILURE, "ioperm");

    outb(0x61, PORT_SMI_CMD);

    printf("done\n");

    return EXIT_SUCCESS;
}
