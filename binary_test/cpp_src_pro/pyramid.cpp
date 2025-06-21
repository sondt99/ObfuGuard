#include <iostream>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Draw a Pyramid ---" << std::endl;
    int height = 7;

    std::cout << "Drawing a pyramid with height " << height << ":" << std::endl;
    for (int i = 1; i <= height; ++i) {
        // Print spaces
        for (int j = 1; j <= height - i; ++j) {
            std::cout << " ";
        }
        // Print stars
        for (int k = 1; k <= 2 * i - 1; ++k) {
            std::cout << "*";
        }
        std::cout << std::endl;
    }
    return 0;
}