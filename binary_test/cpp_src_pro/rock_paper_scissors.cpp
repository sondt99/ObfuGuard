#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Rock, Paper, Scissors ---" << std::endl;
    std::vector<std::string> choices = {"Rock", "Paper", "Scissors"};
    
    std::mt19937 generator(time(0));
    std::uniform_int_distribution<> dist(0, 2);

    int player1_choice = dist(generator);
    int player2_choice = dist(generator);

    std::cout << "Computer 1 chose: " << choices[player1_choice] << std::endl;
    std::cout << "Computer 2 chose: " << choices[player2_choice] << std::endl;

    if (player1_choice == player2_choice) {
        std::cout << "Result: It's a Tie!" << std::endl;
    } else if ((player1_choice == 0 && player2_choice == 2) || // Rock > Scissors
               (player1_choice == 1 && player2_choice == 0) || // Paper > Rock
               (player1_choice == 2 && player2_choice == 1)) { // Scissors > Paper
        std::cout << "Result: Computer 1 Wins!" << std::endl;
    } else {
        std::cout << "Result: Computer 2 Wins!" << std::endl;
    }

    return 0;
}