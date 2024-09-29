#include <iostream>
struct cat {
    const char* name;
    void meow() const { std::cout << "meow\n"; }
};
int main() {
    const char* (cat:: * data_ptr) = &cat::name;
    void (cat:: * func_ptr)() const = &cat::meow;

    cat marshmallow{ "Marshmallow" };

    auto name = marshmallow.*data_ptr;
    (marshmallow.*func_ptr)();
}