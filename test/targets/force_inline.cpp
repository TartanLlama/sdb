#include <cstdio>

__attribute__((always_inline))
void inlined() {
    puts("I am inlined");
}

void not_inlined() {
    inlined();
    puts("I am not inlined");
}

int main() {
    not_inlined();
}