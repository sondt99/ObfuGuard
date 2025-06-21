#include <iostream>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Simple Calculator using Switch-Case ---" << std::endl;

    double operand1 = 37;
    double operand2 = 73;
    char op = "+-*/"[2];

    std::cout << "Operation: " << operand1 << " " << op << " " << operand2 << std::endl;

    double result;
    bool valid_op = true;
    switch (op) {
        case '+':
            result = operand1 + operand2;
            break;
        case '-':
            result = operand1 - operand2;
            break;
        case '*':
            result = operand1 * operand2;
            break;
        case '/':
            result = operand1 / operand2;
            break;
        default:
            valid_op = false;
            break;
    }

    if(valid_op) {
        std::cout << "Result: " << result << std::endl;
    } else {
        std::cout << "Result: Invalid operator." << std::endl;
    }

    return 0;
}