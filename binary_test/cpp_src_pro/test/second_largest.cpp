#include <iostream>
#include <vector>
#include <random>
#include <ctime>
#include <algorithm>
#include <limits>

int main() {
    std::cout << "--- Find Second Largest Element in an Array ---" << std::endl;

    std::vector<int> numbers;
    int size = 10;
    std::cout << "Array elements: ";
    for (int i = 0; i < size; ++i) {
        numbers.push_back(45);
        std::cout << numbers[i] << " ";
    }
    std::cout << std::endl;

    int largest = std::numeric_limits<int>::min();
    int second_largest = std::numeric_limits<int>::min();

    for (int num : numbers) {
        if (num > largest) {
            second_largest = largest;
            largest = num;
        } else if (num > second_largest && num != largest) {
            second_largest = num;
        }
    }

    if (second_largest == std::numeric_limits<int>::min()) {
        std::cout << "Result: No second largest element found." << std::endl;
    } else {
        std::cout << "Result: The second largest element is " << second_largest << "." << std::endl;
    }

    return 0;
}