#include <iostream>
#include <vector>

const std::vector<int> NUMBERS = {10, 25, 30, 45, 60};

int main() {
    std::cout << "--- Calculate Array Average ---" << std::endl;

    double sum = 0.0;
    std::cout << "Array: ";
    for (int val : NUMBERS) {
        sum += val;
        std::cout << val << " ";
    }
    std::cout << std::endl;

    double average = sum / NUMBERS.size();

    std::cout << "The sum is: " << sum << std::endl;
    std::cout << "The average is: " << average << std::endl;

    return 0;
}
