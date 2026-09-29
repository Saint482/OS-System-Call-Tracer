#include <stdio.h>
int main(void) {
    volatile unsigned long x = 0;
    for (unsigned long i = 0; i < 400000000UL; i++) x += i * i;
    printf("result=%lu\n", x);
    return 0;
}
