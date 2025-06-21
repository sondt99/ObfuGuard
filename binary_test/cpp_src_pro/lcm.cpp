#include <iostream>
#include <random>
#include <ctime>

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
    int a = 12;
    int b = 18;
    
    std::cout << "Finding LCM of " << a << " and " << b << std::endl;
    
    long long lcm = (long long)a * b / gcd(a, b);
    
    std::cout << "The LCM is: " << lcm << std::endl;

    return 0;
}