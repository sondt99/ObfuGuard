#include <iostream>
#include <random>
#include <ctime>
#include <algorithm>

int main() {
    std::cout << "--- Find the Largest of Three Numbers ---" << std::endl;
    
    int a = 8;
    int b = 2;
    int c = 14;

    std::cout << "The three random numbers are: " << a << ", " << b << ", " << c << std::endl;
    
    int max_val = std::max({a, b, c});
    
    std::cout << "Result: The largest number is " << max_val << "." << std::endl;
    
    return 0;
}