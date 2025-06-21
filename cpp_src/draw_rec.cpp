#include <iostream>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Draw a Solid Rectangle ---" << std::endl;
    std::mt19937 generator(time(0));
    std::uniform_int_distribution<> dist_w(8, 15);
    std::uniform_int_distribution<> dist_h(4, 7);
    int width = dist_w(generator);
    int height = dist_h(generator);

    std::cout << "Drawing a " << width << "x" << height << " rectangle:" << std::endl;
    for (int i = 0; i < height; ++i) {
        for (int j = 0; j < width; ++j) {
            std::cout << "*";
        }
        std::cout << std::endl;
    }
    return 0;
}