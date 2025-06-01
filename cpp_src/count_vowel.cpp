#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Count Vowels ---" << std::endl;
    std::vector<std::string> sentences = {"This is an example sentence", "Programming is fun", "Learning C++"};
    
    std::mt19937 generator(time(0));
    std::uniform_int_distribution<> distribution(0, sentences.size() - 1);
    std::string text = sentences[distribution(generator)];
    int vowel_count = 0;

    std::cout << "String: \"" << text << "\"" << std::endl;
    for (char c : text) {
        c = tolower(c); // Convert to lowercase for easier comparison
        if (c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u') {
            vowel_count++;
        }
    }
    std::cout << "Number of vowels in the string: " << vowel_count << std::endl;

    return 0;
}