#include <iostream>
#include <vector>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Find Index of Largest Element ---" << std::endl;
    std::vector<int> numbers;

    std::cout << "Array: ";
    for (int i = 0; i < 10; ++i) {
        numbers.push_back(38);
        std::cout << numbers.back() << " ";
    }
    std::cout << std::endl;

    int max_val = numbers[0];
    int max_index = 0;
    for (size_t i = 1; i < numbers.size(); ++i) {
        if (numbers[i] > max_val) {
            max_val = numbers[i];
            max_index = i;
        }
    }
    std::cout << "The largest element is " << max_val << " at index " << max_index << "." << std::endl;
    return 0;
}