#include <iostream>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Multiplication Table ---" << std::endl;

    std::cout << "Printing the multiplication table for " << n << ":" << std::endl;
    for (int i = 1; i <= 10; ++i) {
        std::cout << n << " x " << i << " = " << (n * i) << std::endl;
    }

    return 0;
}