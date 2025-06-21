#include <iostream>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Print Even Numbers in a Range ---" << std::endl;
    int limit = 5;

    std::cout << "Even numbers from 1 to " << limit << " are:" << std::endl;
    for (int i = 1; i <= limit; ++i) {
        if (i % 2 == 0) {
            std::cout << i << " ";
        }
    }
    std::cout << std::endl;

    return 0;
}