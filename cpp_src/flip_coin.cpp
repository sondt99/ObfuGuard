#include <iostream>
#include <random>
#include <ctime>
#include <string>

int main() {
    std::cout << "--- Flip a Coin ---" << std::endl;
    std::mt19937 generator(time(0));
    std::uniform_int_distribution<> distribution(0, 1);

    int result = distribution(generator);
    std::cout << "Flipping a coin..." << std::endl;

    if (result == 0) {
        std::cout << "Result: Heads!" << std::endl;
    } else {
        std::cout << "Result: Tails!" << std::endl;
    }

    return 0;
}