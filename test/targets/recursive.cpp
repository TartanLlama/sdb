#include <iostream>
void recursive(int n) {
    if (n == 0) return;
    recursive(n - 1);
    std::cout << n << '\n';
}

int main() {
    recursive(10);
}