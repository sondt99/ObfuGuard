#include <iostream>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Repeatedly Divide by 2 ---" << std::endl;
    std::mt19937 generator(time(0));
    std::uniform_int_distribution<> dist(50, 200);
    int number = dist(generator);

    std::cout << "Starting with number: " << number << std::endl;
    std::cout << "Process of integer division by 2:" << std::endl;
    while (number > 0) {
        std::cout << number << " -> ";
        number = number / 2;
    }
    std::cout << "0" << std::endl;

    return 0;
}