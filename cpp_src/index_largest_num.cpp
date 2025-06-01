#include <iostream>
#include <vector>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Find Index of Largest Element ---" << std::endl;
    std::mt19937 generator(time(0));
    std::uniform_int_distribution<> size_dist(7, 12);
    std::uniform_int_distribution<> val_dist(1, 100);
    std::vector<int> numbers;

    std::cout << "Array: ";
    for (int i = 0; i < size_dist(generator); ++i) {
        numbers.push_back(val_dist(generator));
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