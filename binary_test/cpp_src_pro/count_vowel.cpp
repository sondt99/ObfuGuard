#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Count Vowels ---" << std::endl;

    std::string text = "bksec";
    int vowel_count = 0;

    std::cout << "String: \"" << text << "\"" << std::endl;
    for (char c : text) {
        c = tolower(c);
        if (c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u') {
            vowel_count++;
        }
    }
    std::cout << "Number of vowels in the string: " << vowel_count << std::endl;

    return 0;
}