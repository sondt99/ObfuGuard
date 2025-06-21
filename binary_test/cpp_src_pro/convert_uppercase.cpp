#include <iostream>
#include <string>
#include <cctype>

int main() {
    std::cout << "--- Convert String to Uppercase ---" << std::endl;

    std::string text = "this is a lowercase sentence.";
    
    std::cout << "Original:  " << text << std::endl;
    
    for (char &c : text) {
        c = std::toupper(c);
    }
    
    std::cout << "Uppercase: " << text << std::endl;

    return 0;
}