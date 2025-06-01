#include <iostream>
#include <random>
#include <ctime>
#include <algorithm> // For std::max

int main() {
    std::cout << "--- Find the Larger Number ---" << std::endl;
    std::mt19937 generator(time(0));
    std::uniform_int_distribution<> distribution(1, 1000);

    int a = distribution(generator);
    int b = distribution(generator);

    std::cout << "Comparing " << a << " and " << b << std::endl;
    std::cout << "The larger number is: " << std::max(a, b) << std::endl;

    return 0;
}