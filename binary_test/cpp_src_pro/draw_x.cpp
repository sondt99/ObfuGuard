#include <iostream>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Draw the Letter X ---" << std::endl;
    int size = 7;

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