#include <iostream>
#include <vector>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Find the Smallest Element ---" << std::endl;
    std::vector<int> numbers={4, 6, 3, 10, 2, 42, 53};

    std::cout << "Array: ";
    for (int number : numbers) {
        std::cout << number << ' ' ;
    }
    std::cout << std::endl;

    int min_val = numbers[0];
    for (int num : numbers) {
        if (num < min_val) {
            min_val = num;
        }
    }

    std::cout << "The smallest element in the array is: " << min_val << std::endl;

    return 0;
}