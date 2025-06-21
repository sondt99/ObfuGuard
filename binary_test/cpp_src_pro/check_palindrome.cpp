#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Palindrome Check ---" << std::endl;
    
    std::string word = "madam";

    std::string reversedWord = "";
    for (int i = word.length() - 1; i >= 0; --i) {
        reversedWord += word[i];
    }

    std::cout << "Checking the word: '" << word << "'" << std::endl;
    if (word == reversedWord) {
        std::cout << "It is a palindrome." << std::endl;
    } else {
        std::cout << "It is not a palindrome." << std::endl;
    }

    return 0;
}
