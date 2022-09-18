all:
	gcc -c -fPIC pam_mini.c -o pam_mini.o -lpam
	gcc pam_mini.o -shared -o pam_mini.so

clean:
	rm pam_mini.so pam_mini.o
