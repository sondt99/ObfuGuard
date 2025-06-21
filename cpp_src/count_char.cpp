#include <iostream>
#include <string>
#include <vector>

// Hằng số cố định
const std::vector<std::string> WORDS = {"Hello", "Programming", "C++ is fun", "Robot"};
const int SELECTED_INDEX = 1; // Chọn phần tử thứ 2 ("Programming")

int main() {
    std::cout << "--- Count Characters in a String ---" << std::endl;

    std::string text = WORDS[SELECTED_INDEX];

    std::cout << "The chosen string is: \"" << text << "\"" << std::endl;
    std::cout << "The number of characters is: " << text.length() << std::endl;

    return 0;
}
