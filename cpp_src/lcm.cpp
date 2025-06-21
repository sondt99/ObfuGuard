#include <iostream>
#include <random>
#include <ctime>

// Function to calculate GCD
int gcd(int a, int b) {
    while (b != 0) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

int main() {
    std::cout << "--- Least Common Multiple (LCM) ---" << std::endl;
    std::mt19937 generator(time(0));
    std::uniform_int_distribution<> dist(5, 30);
    int a = dist(generator);
    int b = dist(generator);
    
    std::cout << "Finding LCM of " << a << " and " << b << std::endl;
    
    // LCM(a, b) = (a * b) / GCD(a, b)
    long long lcm = (long long)a * b / gcd(a, b);
    
    std::cout << "The LCM is: " << lcm << std::endl;

    return 0;
}