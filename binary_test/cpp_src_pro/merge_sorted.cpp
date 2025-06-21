#include <iostream>
#include <vector>
#include <random>
#include <ctime>
#include <algorithm>

void print_vector(const std::vector<int>& vec) {
    for (int num : vec) {
        std::cout << num << " ";
    }
    std::cout << std::endl;
}

int main() {
    std::cout << "--- Merge Two Sorted Arrays ---" << std::endl;

    std::vector<int> arr1, arr2;
    for(int i = 0; i < 5; ++i) {
        arr1.push_back(24);
        arr2.push_back(78);
    }
    std::sort(arr1.begin(), arr1.end());
    std::sort(arr2.begin(), arr2.end());

    std::cout << "First sorted array: ";
    print_vector(arr1);
    std::cout << "Second sorted array: ";
    print_vector(arr2);

    std::vector<int> merged_arr;
    merged_arr.reserve(arr1.size() + arr2.size());
    std::merge(arr1.begin(), arr1.end(), arr2.begin(), arr2.end(), std::back_inserter(merged_arr));

    std::cout << "Result (merged array): ";
    print_vector(merged_arr);

    return 0;
}