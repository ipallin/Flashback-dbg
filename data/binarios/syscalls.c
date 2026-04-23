#include <unistd.h>
int main(void) {
    const char *msg = "hola via syscall\n";
    long ret;
    asm volatile ("syscall" : "=a"(ret) : "0"(1), "D"(1), "S"(msg), "d"(17) : "rcx", "r11", "memory");
    return 0;
}