#include <iostream>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Calculate Power of a Number (x^y) ---" << std::endl;
    std::mt19937 generator(time(0));
    std::uniform_int_distribution<> base_dist(2, 5);
    std::uniform_int_distribution<> exp_dist(2, 6);
    
    int base = 3;
    int exponent = 3;
    
    std::cout << "Calculating " << base << " to the power of " << exponent << "." << std::endl;
    
    long long result = 1;
    for (int i = 0; i < exponent; ++i) {
        result *= base;
    }
    
    std::cout << "Result: " << base << "^" << exponent << " = " << result << std::endl;
    
    return 0;
}