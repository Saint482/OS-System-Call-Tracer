#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
int main(void) {
    int fd = open("test.txt", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    for (int i = 0; i < 50; i++) write(fd, "hello world\n", 12);
    close(fd);
    char buf[64];
    fd = open("test.txt", O_RDONLY);
    while (read(fd, buf, sizeof buf) > 0) ;
    close(fd);
    unlink("test.txt");
    printf("done\n");
    return 0;
}
