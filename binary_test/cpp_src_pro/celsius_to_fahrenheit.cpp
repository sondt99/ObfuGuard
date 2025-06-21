#include <iostream>
#include <random>
#include <ctime>
#include <iomanip>

int main() {
    std::cout << "--- Celsius to Fahrenheit Conversion ---" << std::endl;
    
    double celsius = 13.1;
    
    double fahrenheit = (celsius * 9.0 / 5.0) + 32;

    std::cout << std::fixed << std::setprecision(2);
    std::cout << celsius << " degrees Celsius is equal to " << fahrenheit << " degrees Fahrenheit." << std::endl;

    return 0;
}