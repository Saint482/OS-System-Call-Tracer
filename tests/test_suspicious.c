#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
int main(void) {
    for (int i = 0; i < 4; i++) open("/etc/shadow", O_RDONLY);   /* ควรโดน Permission denied */
    open("/nonexistent/file", O_RDONLY);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(9) };
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    connect(s, (struct sockaddr *)&a, sizeof a);
    close(s);
    execl("/bin/echo", "echo", "spawned", (char *)0);
    return 0;
}
