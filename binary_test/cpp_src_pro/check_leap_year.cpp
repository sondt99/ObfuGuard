#include <iostream>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Check a Leap Year ---" << std::endl;

    int year = 2025;

    std::cout << "Checking year: " << year << std::endl;

    bool isLeapYear = ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0));

    if (isLeapYear) {
        std::cout << year << " is a leap year." << std::endl;
    } else {
        std::cout << year << " is not a leap year." << std::endl;
    }

    return 0;
}