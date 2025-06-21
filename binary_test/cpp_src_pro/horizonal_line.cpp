#include <iostream>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Draw a Horizontal Line ---" << std::endl;
    const int length = 15;

    std::cout << "Drawing a horizontal line of length " << length << ":" << std::endl;
    for (int i = 0; i < length; ++i) {
        std::cout << "-";
    }
    std::cout << std::endl;
    return 0;
}