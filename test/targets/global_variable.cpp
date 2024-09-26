#include <cstdint>
std::uint64_t g_int = 0;

int main() {
    g_int = 1;
    g_int = 42;
}

struct cat {
    const char* name;
    int age : 5;
    int color : 3;
};

struct person {
    const char* name;
    int age;
    cat* pets;
    int num_pets;
};

cat marshmallow{ "Marshmallow", 4, 1 };
cat lexical_cat{ "Lexical Cat", 8, 2 };
cat milkshake{ "Milkshake", 4, 3 };
cat cats[] = { marshmallow, lexical_cat, milkshake };
person sy{ "Sy", 33, cats, 3 };