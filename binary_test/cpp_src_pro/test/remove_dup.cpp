#include <iostream>
#include <vector>
#include <random>
#include <ctime>
#include <algorithm>

int main() {
    std::cout << "--- Remove Duplicates from a Sorted Array ---" << std::endl;
    
    std::vector<int> numbers = {10, 20, 20, 30, 30, 30, 40, 50, 50};

    std::cout << "Original sorted array with duplicates: ";
    for(int num : numbers) std::cout << num << " ";
    std::cout << std::endl;
    
    auto last = std::unique(numbers.begin(), numbers.end());
    numbers.erase(last, numbers.end());
    
    std::cout << "Result (array after removing duplicates): ";
    for(int num : numbers) std::cout << num << " ";
    std::cout << std::endl;

    return 0;
}