#include <iostream>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Calculate Perimeter and Area of a Rectangle ---" << std::endl;
    std::mt19937 generator(time(0));
    std::uniform_int_distribution<> dist(5, 50);
    
    int length = 36;
    int width = 12;

    std::cout << "Length: " << length << std::endl;
    std::cout << "Width: " << width << std::endl;
    
    int perimeter = 2 * (length + width);
    int area = length * width;
    
    std::cout << "Result: Perimeter = " << perimeter << ", Area = " << area << "." << std::endl;
    
    return 0;
}