#include <iostream>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Draw a Hollow Rectangle ---" << std::endl;
    int width = 3;
    int height = 6;

    std::cout << "Drawing a hollow " << width << "x" << height << " rectangle:" << std::endl;
    for (int i = 0; i < height; ++i) {
        for (int j = 0; j < width; ++j) {
            if (i == 0 || i == height - 1 || j == 0 || j == width - 1) {
                std::cout << "* ";
            } else {
                std::cout << "  ";
            }
        }
        std::cout << std::endl;
    }
    return 0;
}