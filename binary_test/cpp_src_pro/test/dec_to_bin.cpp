#include <iostream>
#include <string>
#include <random>
#include <ctime>
#include <algorithm>

int main() {
    std::cout << "--- Decimal to Binary Conversion ---" << std::endl;

    int decimal_num = 36;
    std::cout << "Decimal number: " << decimal_num << std::endl;

    if (decimal_num == 0) {
        std::cout << "Result: Binary representation is 0" << std::endl;
        return 0;
    }

    std::string binary_str = "";
    int temp = decimal_num;
    while (temp > 0) {
        binary_str += (temp % 2 == 0 ? "0" : "1");
        temp /= 2;
    }
    std::reverse(binary_str.begin(), binary_str.end());

    std::cout << "Result: Binary representation is " << binary_str << std::endl;

    return 0;
}