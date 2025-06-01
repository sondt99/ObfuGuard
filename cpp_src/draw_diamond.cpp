#include <iostream>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Draw a Diamond ---" << std::endl;
    std::mt19937 generator(time(0));
    std::uniform_int_distribution<> distribution(4, 7);
    int h = distribution(generator); // half-height

    std::cout << "Drawing a diamond with half-height " << h << ":" << std::endl;
    // Top half
    for (int i = 1; i <= h; ++i) {
        for (int j = 1; j <= h - i; ++j) std::cout << " ";
        for (int k = 1; k <= 2 * i - 1; ++k) std::cout << "*";
        std::cout << std::endl;
    }
    // Bottom half
    for (int i = h - 1; i >= 1; --i) {
        for (int j = 1; j <= h - i; ++j) std::cout << " ";
        for (int k = 1; k <= 2 * i - 1; ++k) std::cout << "*";
        std::cout << std::endl;
    }
    return 0;
}