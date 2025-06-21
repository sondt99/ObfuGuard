#include <iostream>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Access Array Elements using Pointers ---" << std::endl;
    int arr[5];

    std::cout << "Original array: ";
    for (int i = 0; i < 5; ++i) {
        arr[i] = 34;
        std::cout << arr[i] << " ";
    }
    std::cout << std::endl;

    int* ptr = arr;

    std::cout << "Result (accessing via pointer):" << std::endl;
    for (int i = 0; i < 5; ++i) {
        std::cout << "  Value at address " << (ptr + i) << " is " << *(ptr + i) << std::endl;
    }
    
    return 0;
}