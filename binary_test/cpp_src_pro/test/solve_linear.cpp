#include <iostream>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Solve a Linear Equation (ax + b = 0) ---" << std::endl;
    std::mt19937 generator(time(0));
    std::uniform_int_distribution<> dist_a(1, 10);
    std::uniform_int_distribution<> dist_b(-50, 50);
    
    int a = 6;
    int b = 9;

    std::cout << "Equation: " << a << "x + " << b << " = 0" << std::endl;
    
    double x = -static_cast<double>(b) / a;
    
    std::cout << "Result: x = " << x << std::endl;
    
    return 0;
}