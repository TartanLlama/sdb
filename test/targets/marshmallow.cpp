#include <iostream>
int libmeow_client_cuteness = 100;
bool libmeow_client_is_cute();

int main() {
    std::cout << "Cuteness rating: " << libmeow_client_cuteness << '\n';
    std::cout << "Is cute: " << std::boolalpha << libmeow_client_is_cute() << '\n';
}