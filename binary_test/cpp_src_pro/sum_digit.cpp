#include <iostream>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Sum of Digits ---" << std::endl;

    int number = 19823;
    
    int originalNumber = number;
    int sum = 0;

    while (number > 0) {
        sum += number % 10;
        number /= 10;
    }

    std::cout << "The sum of the digits in " << originalNumber << " is " << sum << std::endl;

    return 0;
}