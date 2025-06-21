#include <iostream>
#include <random>
#include <ctime>
#include <cmath> 

int main() {
    std::cout << "--- Power Calculation ---" << std::endl;
    int a = 4;
    int b = 3;
    long long result = pow(a, b);

    std::cout << "Calculating " << a << " to the power of " << b << std::endl;
    std::cout << "Result: " << result << std::endl;

    return 0;
}