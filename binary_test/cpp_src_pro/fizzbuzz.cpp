#include <iostream>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- The FizzBuzz Game ---" << std::endl;
    int n = 17;

    std::cout << "Playing FizzBuzz from 1 to " << n << ":" << std::endl;
    for (int i = 1; i <= n; ++i) {
        if (i % 15 == 0) {
            std::cout << "FizzBuzz ";
        } else if (i % 3 == 0) {
            std::cout << "Fizz ";
        } else if (i % 5 == 0) {
            std::cout << "Buzz ";
        } else {
            std::cout << i << " ";
        }
    }
    std::cout << std::endl;
    return 0;
}