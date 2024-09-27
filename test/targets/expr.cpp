#include <iostream>
#include <cstring>
#include <cstdint>

struct cat {
    const char* name;
    int age;
    void give_command(const char* command);
    void increase_age();
};
void cat::give_command(const char* command) {
    std::cout << name << ", " << command << std::endl;
}
void cat::increase_age() {
    age++;
}

cat marshmallow{ "Marshmallow", 4 };
cat milkshake{ "Milkshake", 4 };
cat lexa{ "Lexa", 8 };

cat get_cat(const char* name) {
    for (auto c : { marshmallow, milkshake, lexa }) {
        if (strcmp(c.name, name) == 0) {
            return c;
        }
    }
}

int print_type(int i) {
    std::cout << "int " << i << '\n';
    return i;
}

double print_type(double d) {
    std::cout << "double " << d << '\n';
    return d;
}

const char* print_type(const char* s) {
    std::cout << "string " << s << '\n';
    return s;
}

char print_type(char c) {
    std::cout << "char " << c << '\n';
    return c;
}

struct small {
    int i, j;
};

struct two_eightbyte {
    std::uint64_t i, j;
};

struct big {
    std::uint64_t i, j, k;
};

small print_type(small s) {
    std::cout << "small " << s.i << ' ' << s.j << '\n';
    return s;
}

two_eightbyte print_type(two_eightbyte t) {
    std::cout << "two_eightbyte " << t.i << ' ' << t.j << '\n';
    return t;
}

big print_type(big b) {
    std::cout << "bigg " << b.i << ' ' << b.j << ' ' << b.k << '\n';
    return b;
}

small s = { 1, 2 };
two_eightbyte t = { 3, 4 };
big b = { 5, 6, 7 };

int main() {

}