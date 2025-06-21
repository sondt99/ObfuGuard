#include <iostream>
#include <vector>
#include <random>
#include <ctime>
#include <numeric>

int main() {
    std::cout << "--- Find the Missing Number in a Sequence ---" << std::endl;
    int n = 10;
    
    int missing_number = 5;
    std::vector<int> numbers;
    long long current_sum = 0;
    
    std::cout << "Sequence of 1 to " << n << " with one number missing." << std::endl;
    std::cout << "The missing number is secretly: " << missing_number << std::endl;

    for (int i = 1; i <= n; ++i) {
        if (i != missing_number) {
            numbers.push_back(i);
            current_sum += i;
        }
    }
    
    long long expected_sum = static_cast<long long>(n) * (n + 1) / 2;
    long long found_missing = expected_sum - current_sum;
    
    std::cout << "Result: The missing number found by calculation is " << found_missing << "." << std::endl;

    return 0;
}