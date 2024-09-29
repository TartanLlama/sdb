#include <string>
#include <iostream>

void print_type(int) {
    std::cout << "int";
}

void print_type(double) {
    std::cout << "double";
}

void print_type(std::string) {
    std::cout << "string";
}

int main() {
    print_type(0);
    print_type(1.4);
    print_type("hello");
}