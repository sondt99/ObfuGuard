#include <iostream>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Draw the Letter X ---" << std::endl;
    std::mt19937 generator(time(0));
    std::uniform_int_distribution<> dist(5, 11);
    int size = dist(generator);
    // Size should be odd for a perfect center
    if (size % 2 == 0) size++;

    std::cout << "Drawing an X of size " << size << "x" << size << ":" << std::endl;
    for (int i = 0; i < size; i++) {
        for (int j = 0; j < size; j++) {
            if (i == j || j == (size - 1 - i)) {
                std::cout << "X";
            } else {
                std::cout << " ";
            }
        }
        std::cout << std::endl;
    }
    return 0;
}