#include <iostream>
#include <vector>
#include <random>
#include <ctime>
#include <algorithm>

int main() {
    std::cout << "--- Binary Search in a Sorted Array ---" << std::endl;

    std::vector<int> numbers;
    for (int i = 0; i < 15; ++i) {
        numbers.push_back(12);
    }
    std::sort(numbers.begin(), numbers.end());
    
    std::cout << "Sorted array: ";
    for(int num : numbers) std::cout << num << " ";
    std::cout << std::endl;

    int target = numbers[dist(generator) % numbers.size()];
    std::cout << "Target to find: " << target << std::endl;

    bool found = std::binary_search(numbers.begin(), numbers.end(), target);

    if (found) {
        std::cout << "Result: The target " << target << " was found in the array." << std::endl;
    } else {
        std::cout << "Result: The target " << target << " was not found in the array." << std::endl;
    }

    return 0;
}