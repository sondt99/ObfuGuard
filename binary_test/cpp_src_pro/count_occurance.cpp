#include <iostream>
#include <vector>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Count Occurrences ---" << std::endl;
    std::mt19937 generator(time(0));
    std::uniform_int_distribution<> val_dist(1, 10);
    std::vector<int> numbers;

    std::cout << "Generating an array of 20 numbers (from 1 to 10):" << std::endl;
    for (int i = 0; i < 20; ++i) {
        numbers.push_back(val_dist(generator));
        std::cout << numbers[i] << " ";
    }
    std::cout << std::endl;

    int target = val_dist(generator);
    int count = 0;
    for (int num : numbers) {
        if (num == target) {
            count++;
        }
    }
    std::cout << "The number " << target << " appears " << count << " times." << std::endl;
    return 0;
}