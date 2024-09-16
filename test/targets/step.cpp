#include <cstdio>

__attribute__((always_inline))
inline void scratch_ears() {
	std::puts("Scratching ears");
}

__attribute__((always_inline))
inline void pet_cat() {
	scratch_ears();
	std::puts("Done petting cat");
}

void find_happiness() {
	pet_cat();
	std::puts("Found happiness");
}

int main() {
	find_happiness();
	find_happiness();
}