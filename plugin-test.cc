#include <stdio.h>

// our instrumentation runtime machinery
extern "C" {
    __attribute__((used)) void __aspect_log_f()
    {
        printf("aspect-plugin [RUN]: instrumented\n");
    }
}

[[viscon::aspect]] void foo_log()
{
    printf("foo enter\n"); // if format string given, too long for Three Address Code single stment.

    int x, y;
    
    x ^= y;
    y ^= x;
    x ^= y;

    printf("foo exit\n");
    return;
}

int main()
{
    printf("main\n");
    foo_log();
    return 1;
}