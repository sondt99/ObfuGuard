#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Count Characters in a String ---" << std::endl;
    
    std::string text = "Programming";

    std::cout << "The chosen string is: \"" << text << "\"" << std::endl;
    std::cout << "The number of characters is: " << text.length() << std::endl;

    return 0;
}