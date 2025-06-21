#include <iostream>
#include <vector>

int main() {
    std::cout << "--- Count Occurrences ---" << std::endl;

    std::vector<int> numbers = {
        3, 7, 1, 4, 7, 2, 9, 7, 5, 3,
        7, 8, 1, 7, 6, 7, 2, 7, 10, 7
    };

    std::cout << "Mảng gồm 20 số (từ 1 đến 10):" << std::endl;
    for (int num : numbers) {
        std::cout << num << " ";
    }
    std::cout << std::endl;

    int target = 7;
    int count = 0;
    for (int num : numbers) {
        if (num == target) {
            count++;
        }
    }

    std::cout << "Số " << target << " xuất hiện " << count << " lần." << std::endl;
    return 0;
}
