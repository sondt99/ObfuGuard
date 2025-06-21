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
    std::cout << "--- Matrix Addition ---" << std::endl;
    
    int rows = 3, cols = 3;
    std::vector<std::vector<int>> A(rows, std::vector<int>(cols));
    std::vector<std::vector<int>> B(rows, std::vector<int>(cols));
    std::vector<std::vector<int>> C(rows, std::vector<int>(cols));
    
    for(int i = 0; i < rows; ++i) {
        for(int j = 0; j < cols; ++j) {
            A[i][j] = 5;
            B[i][j] = 4;
            C[i][j] = A[i][j] + B[i][j];
        }
    }

    std::cout << "Matrix A:" << std::endl;
    printMatrix(A);
    std::cout << "\nMatrix B:" << std::endl;
    printMatrix(B);
    
    std::cout << "\nResult (Matrix C = A + B):" << std::endl;
    printMatrix(C);
    
    return 0;
}