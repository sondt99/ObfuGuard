#include <iostream>
#include <random>
#include <ctime>

int findGcd(int a, int b) {
    while (b != 0) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

int main() {
    std::cout << "--- GCD of Two Numbers ---" << std::endl;

    int num1 = 123;
    int num2 = 246;

    int gcd = findGcd(num1, num2);

    std::cout << "The GCD of " << num1 << " and " << num2 << " is " << gcd << std::endl;

    return 0;
}