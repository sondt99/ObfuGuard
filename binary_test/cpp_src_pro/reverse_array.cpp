#include <iostream>
#include <vector>
#include <algorithm>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Reverse an Array ---" << std::endl;

    std::mt19937 generator(time(0));
    std::uniform_int_distribution<> distribution(1, 99);
    std::vector<int> datas={5, 3, 8, 1};

    std::cout << "Original array: ";
    for (int data : datas) {
        std::cout << data << " ";
    }
    std::cout << std::endl;

    std::reverse(datas.begin(), datas.end());

    std::cout << "Reversed array: ";
    for (int data : datas) {
        std::cout << data << " ";
    }
    std::cout << std::endl;

    return 0;
}