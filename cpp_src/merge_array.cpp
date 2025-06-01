#include <iostream>
#include <vector>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Merge Two Arrays ---" << std::endl;
    std::mt19937 generator(time(0));
    std::uniform_int_distribution<> size_dist(3, 5);
    std::uniform_int_distribution<> val_dist(1, 100);
    std::vector<int> arr1, arr2;

    std::cout << "Array 1: ";
    for (int i = 0; i < size_dist(generator); ++i) {
        arr1.push_back(val_dist(generator));
        std::cout << arr1.back() << " ";
    }
    std::cout << std::endl;

    std::cout << "Array 2: ";
    for (int i = 0; i < size_dist(generator); ++i) {
        arr2.push_back(val_dist(generator));
        std::cout << arr2.back() << " ";
    }
    std::cout << std::endl;

    std::vector<int> merged_arr = arr1;
    merged_arr.insert(merged_arr.end(), arr2.begin(), arr2.end());

    std::cout << "Merged array: ";
    for (int num : merged_arr) {
        std::cout << num << " ";
    }
    std::cout << std::endl;

    return 0;
}