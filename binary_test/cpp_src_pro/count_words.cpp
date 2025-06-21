#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Count Words in a Sentence ---" << std::endl;

    std::string sentence = "The sky is blue today";

    int word_count = 1; // Start at 1 because the last word doesn't have a space after it
    if (sentence.empty()) {
        word_count = 0;
    }

    std::cout << "Sentence: \"" << sentence << "\"" << std::endl;
    for (char c : sentence) {
        if (c == ' ') {
            word_count++;
        }
    }

    std::cout << "This sentence has " << word_count << " words." << std::endl;
    return 0;
}