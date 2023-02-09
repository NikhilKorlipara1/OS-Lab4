all: nyufile

nyufile: nyufile.c
	gcc -o nyufile nyufile.c -lcrypto

clean:
	rm -f nyufile
