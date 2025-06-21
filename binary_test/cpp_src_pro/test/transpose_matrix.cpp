#include <iostream>
#include <vector>
#include <random>
#include <ctime>

void printMatrix(const std::vector<std::vector<int>>& matrix) {
    for (const auto& row : matrix) {
        for (int val : row) {
            std::cout << val << "\t";
        }
        std::cout << std::endl;
    }
}

int main() {
    std::cout << "--- Transpose of a Matrix ---" << std::endl;

    int rows = 2, cols = 4;
    std::vector<std::vector<int>> matrix(rows, std::vector<int>(cols));
    for(int i = 0; i < rows; ++i) {
        for(int j = 0; j < cols; ++j) {
            matrix[i][j] = 3;
        }
    }

    std::cout << "Original Matrix (" << rows << "x" << cols << "):" << std::endl;
    printMatrix(matrix);

    std::vector<std::vector<int>> transpose(cols, std::vector<int>(rows));
    for(int i = 0; i < rows; ++i) {
        for(int j = 0; j < cols; ++j) {
            transpose[j][i] = matrix[i][j];
        }
    }

    std::cout << "\nResult (Transposed Matrix, " << cols << "x" << rows << "):" << std::endl;
    printMatrix(transpose);

    return 0;
}