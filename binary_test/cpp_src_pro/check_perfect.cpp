#include <iostream>
#include <random>
#include <ctime>
#include <vector>

int main() {
    std::cout << "--- Check for a Perfect Number ---" << std::endl;
    
    int number = 496;
    std::cout << "Number to check: " << number << std::endl;

    int sum_of_divisors = 0;
    for (int i = 1; i <= number / 2; ++i) {
        if (number % i == 0) {
            sum_of_divisors += i;
        }
    }

    if (sum_of_divisors == number && number != 0) {
        std::cout << "Result: " << number << " is a perfect number." << std::endl;
    } else {
        std::cout << "Result: " << number << " is not a perfect number." << std::endl;
    }

    return 0;
}