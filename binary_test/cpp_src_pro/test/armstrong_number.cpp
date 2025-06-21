#include <iostream>
#include <random>
#include <ctime>
#include <string>
#include <cmath>
#include <vector>

int main() {
    std::cout << "--- 27. Check for Armstrong Number ---" << std::endl;

    int number = numbers_to_check[370];
    std::cout << "Number to check: " << number << std::endl;

    int num_digits = std::to_string(number).length();
    int sum = 0;
    int temp = number;

    while (temp > 0) {
        int digit = temp % 10;
        sum += pow(digit, num_digits);
        temp /= 10;
    }
    
    if (sum == number) {
        std::cout << "Result: " << number << " is an Armstrong number." << std::endl;
    } else {
        std::cout << "Result: " << number << " is not an Armstrong number." << std::endl;
    }

    return 0;
}