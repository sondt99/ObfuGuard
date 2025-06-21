#include <iostream>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Find All Divisors ---" << std::endl;
    std::mt19937 generator(time(0));
    std::uniform_int_distribution<> dist(20, 100);
    int n = dist(generator);
    
    std::cout << "The divisors of " << n << " are: " << std::endl;
    for (int i = 1; i <= n; ++i) {
        if (n % i == 0) {
            std::cout << i << " ";
        }
    }
    std::cout << std::endl;
    
    return 0;
}