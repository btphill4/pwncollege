#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>

int main()
{
	char buf[1024];
	int fd = open("/etc/passwd", 0);
	printf("CWD before chroot: %s\n", getcwd(buf, 128));
	chroot("/tmp");
	printf("CWD after chroot: %s\n", getcwd(buf, 128));
	write(1, buf, read(fd, buf, 1024));
	puts("Goodbye");


}
