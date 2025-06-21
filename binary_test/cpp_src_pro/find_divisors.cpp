#include <iostream>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Find All Divisors ---" << std::endl;
    int n = 64;
    
    std::cout << "The divisors of " << n << " are: " << std::endl;
    for (int i = 1; i <= n; ++i) {
        if (n % i == 0) {
            std::cout << i << " ";
        }
    }
    std::cout << std::endl;
    
    return 0;
}