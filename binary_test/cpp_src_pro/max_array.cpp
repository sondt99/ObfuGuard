#include <iostream>
#include <vector>

int main() {
    std::cout << "--- Find Maximum in Array ---" << std::endl;

    std::vector<int> numbers = {34, -5, 88, 12, 99, 0, -42, 101};

    std::cout << "The array is: ";
    for (int num : numbers) {
        std::cout << num << " ";
    }
    std::cout << std::endl;

    if (numbers.empty()) {
        std::cout << "The array is empty." << std::endl;
    } else {
        int maxNumber = numbers[0];
        for (size_t i = 1; i < numbers.size(); ++i) {
            if (numbers[i] > maxNumber) {
                maxNumber = numbers[i];
            }
        }
        std::cout << "The maximum number is: " << maxNumber << std::endl;
    }

    return 0;
}