#include <iostream>
#include <random>
#include <ctime>
#include <algorithm> // For std::max

int main() {
    std::cout << "--- Find the Larger Number ---" << std::endl;

    int a = 6;
    int b = 2;

    std::cout << "Comparing " << a << " and " << b << std::endl;
    std::cout << "The larger number is: " << std::max(a, b) << std::endl;

    return 0;
}