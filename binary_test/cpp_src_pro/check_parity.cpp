#include <iostream>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Check Even or Odd ---" << std::endl;
    
    int randomNumber = 26;

    std::cout << "The number is: " << randomNumber << std::endl;

    if (randomNumber % 2 == 0) {
        std::cout << randomNumber << " is an even number." << std::endl;
    } else {
        std::cout << randomNumber << " is an odd number." << std::endl;
    }

    return 0;
}