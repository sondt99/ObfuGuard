#include <iostream>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Draw a Hollow Rectangle ---" << std::endl;
    std::mt19937 generator(time(0));
    std::uniform_int_distribution<> dist_w(10, 20);
    std::uniform_int_distribution<> dist_h(5, 10);
    int width = dist_w(generator);
    int height = dist_h(generator);

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