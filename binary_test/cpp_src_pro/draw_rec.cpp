#include <iostream>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Draw a Solid Rectangle ---" << std::endl;
    int width = 3;
    int height = 6;

    std::cout << "Drawing a " << width << "x" << height << " rectangle:" << std::endl;
    for (int i = 0; i < height; ++i) {
        for (int j = 0; j < width; ++j) {
            std::cout << "*";
        }
        std::cout << std::endl;
    }
    return 0;
}