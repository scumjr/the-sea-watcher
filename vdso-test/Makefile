CFLAGS=-W -Wall

all: vdso-test

vdso-test: vdso-test.o ../payload.o vdso vdso-backdoored
	$(CC) -o $@ $< $(LDFLAGS)

vdso-backdoored: vdso
	./backdoor-vdso.py

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

clean:
	rm -f *.o vdso-test vdso-backdoored
