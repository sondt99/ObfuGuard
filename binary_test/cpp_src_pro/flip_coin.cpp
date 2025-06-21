#include <iostream>
#include <random>
#include <ctime>
#include <string>

int main() {
    std::cout << "--- Flip a Coin ---" << std::endl;

    int result = 1;
    std::cout << "Flipping a coin..." << std::endl;

    if (result == 0) {
        std::cout << "Result: Heads!" << std::endl;
    } else {
        std::cout << "Result: Tails!" << std::endl;
    }

    return 0;
}