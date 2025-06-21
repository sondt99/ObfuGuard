#include <iostream>
#include <string>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Traffic Light Simulation ---" << std::endl;
    int state = 1;
    
    std::cout << "Current light state: ";
    if (state == 1) {
        std::cout << "GREEN. You can go!" << std::endl;
    } else if (state == 2) {
        std::cout << "YELLOW. Prepare to stop!" << std::endl;
    } else {
        std::cout << "RED. Please stop!" << std::endl;
    }

    return 0;
}