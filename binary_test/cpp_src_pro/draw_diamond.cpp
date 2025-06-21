#include <iostream>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Draw a Diamond ---" << std::endl;
    int h = 6;

    std::cout << "Drawing a diamond with half-height " << h << ":" << std::endl;
    for (int i = 1; i <= h; ++i) {
        for (int j = 1; j <= h - i; ++j) std::cout << " ";
        for (int k = 1; k <= 2 * i - 1; ++k) std::cout << "*";
        std::cout << std::endl;
    }
    for (int i = h - 1; i >= 1; --i) {
        for (int j = 1; j <= h - i; ++j) std::cout << " ";
        for (int k = 1; k <= 2 * i - 1; ++k) std::cout << "*";
        std::cout << std::endl;
    }
    return 0;
}