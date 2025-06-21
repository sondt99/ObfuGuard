#include <iostream>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Triangle of Random Height ---" << std::endl;

    const int height = 7;

    std::cout << "Drawing a triangle with height " << height << ":" << std::endl;
    for (int i = 1; i <= height; ++i) {
        for (int j = 1; j <= i; ++j) {
            std::cout << "# ";
        }
        std::cout << std::endl;
    }

    return 0;
}