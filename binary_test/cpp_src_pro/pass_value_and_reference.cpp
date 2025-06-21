#include <iostream>
#include <random>
#include <ctime>

void incrementByValue(int val) {
    val++;
}

void incrementByReference(int &ref) {
    ref++;
}

int main() {
    std::cout << "--- Pass by Value vs. Pass by Reference ---" << std::endl;
    
    int num = 23;
    std::cout << "Initial value of num: " << num << std::endl;

    incrementByValue(num);
    std::cout << "Value after incrementByValue call: " << num << std::endl;

    incrementByReference(num);
    std::cout << "Value after incrementByReference call: " << num << std::endl;

    return 0;
}