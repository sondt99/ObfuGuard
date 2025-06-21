#include <iostream>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Draw a Horizontal Line ---" << std::endl;
    std::mt19937 generator(time(0));
    std::uniform_int_distribution<> distribution(10, 30);
    const int length = distribution(generator);

    std::cout << "Drawing a horizontal line of length " << length << ":" << std::endl;
    for (int i = 0; i < length; ++i) {
        std::cout << "-";
    }
    std::cout << std::endl;
    return 0;
}