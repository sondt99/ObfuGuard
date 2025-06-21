#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Count Words in a Sentence ---" << std::endl;
    std::vector<std::string> sentences = {
        "The sky is blue today", 
        "We are learning to code", 
        "C++ is an interesting language"
    };
    
    std::mt19937 generator(time(0));
    std::uniform_int_distribution<> dist(0, sentences.size() - 1);
    std::string sentence = sentences[dist(generator)];

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