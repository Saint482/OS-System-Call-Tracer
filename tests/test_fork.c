#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
int main(void) {
    pid_t pid = fork();
    if (pid == 0) { printf("child pid=%d\n", getpid()); _exit(3); }
    int st; waitpid(pid, &st, 0);
    printf("parent: child exited %d\n", WEXITSTATUS(st));
    return 0;
}
