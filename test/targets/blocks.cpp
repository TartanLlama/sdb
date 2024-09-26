#include <iostream>
int main(int argc, const char** argv) {
    int i = 1;
    std::cout << i;
    {
        int i = 2;
        std::cout << i;
        {
            int i = 3;
            std::cout << i;
        }
    }
}