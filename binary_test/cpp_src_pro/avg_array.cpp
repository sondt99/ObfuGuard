#include <iostream>
#include <vector>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Calculate Array Average ---" << std::endl;
    int size = 8;
    std::vector<int> numbers;
    double sum = 0.0;

    std::cout << "Random array: ";
    for (int i = 0; i < size; ++i) {
        int val = 4;
        numbers.push_back(val);
        sum += val;
        std::cout << val << " ";
    }
    std::cout << std::endl;
    
    double average = sum / numbers.size();
    
    std::cout << "The sum is: " << sum << std::endl;
    std::cout << "The average is: " << average << std::endl;

    return 0;
}