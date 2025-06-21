#include <iostream>
#include <string>
#include <random>
#include <ctime>
#include <algorithm>

int main() {
    std::cout << "--- Check if Two Strings are Anagrams ---" << std::endl;
    std::string s1 = "listen";
    std::string s2 = "silent";

    std::cout << "First string: " << s1 << std::endl;
    std::cout << "Second string: " << s2 << std::endl;

    if (s1.length() != s2.length()) {
        std::cout << "Result: The strings are not anagrams." << std::endl;
        return 0;
    }
    
    std::sort(s1.begin(), s1.end());
    std::sort(s2.begin(), s2.end());
    
    if (s1 == s2) {
        std::cout << "Result: The strings are anagrams." << std::endl;
    } else {
        std::cout << "Result: The strings are not anagrams." << std::endl;
    }

    return 0;
}