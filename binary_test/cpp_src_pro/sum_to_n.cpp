#include <iostream>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Sum from 1 to N ---" << std::endl;
    int n = 7;
    int sum = 0;

    std::cout << "Calculating the sum of numbers from 1 to " << n << std::endl;
    for (int i = 1; i <= n; ++i) {
        sum += i;
    }
    std::cout << "The sum is: " << sum << std::endl;

    return 0;
}