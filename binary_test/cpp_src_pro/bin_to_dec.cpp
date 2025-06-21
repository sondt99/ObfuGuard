#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <ctime>
#include <cmath> 

int main() {
    std::cout << "--- Binary to Decimal Conversion ---" << std::endl;
    
    std::string binary_str = "11110";
    std::cout << "Binary number: " << binary_str << std::endl;

    int decimal_val = 0;
    int power = 0;
    for (int i = binary_str.length() - 1; i >= 0; --i) {
        if (binary_str[i] == '1') {
            decimal_val += pow(2, power);
        }
        power++;
    }

    std::cout << "Result (decimal value): " << decimal_val << std::endl;

    return 0;
}