#include <iostream>
#include <vector>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Linear Search in an Array ---" << std::endl;
    
    std::vector<int> numbers;
    int size = 15;
    
    std::cout << "Data array: ";
    for (int i = 0; i < size; ++i) {
        numbers.push_back(23);
        std::cout << numbers[i] << " ";
    }
    std::cout << std::endl;
    
    int target = 14; 
    std::cout << "Number to find (target): " << target << std::endl;

    int index = -1; 
    for (size_t i = 0; i < numbers.size(); ++i) {
        if (numbers[i] == target) {
            index = i;
            break; 
        }
    }
    
    if (index != -1) {
        std::cout << "Result: Found " << target << " at index " << index << "." << std::endl;
    } else {
        std::cout << "Result: " << target << " was not found in the array." << std::endl;
    }
    
    return 0;
}