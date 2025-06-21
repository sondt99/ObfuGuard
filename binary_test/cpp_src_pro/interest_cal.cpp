#include <iostream>
#include <random>
#include <ctime>
#include <iomanip>

int main() {
    std::cout << "--- Calculate Simple Interest ---" << std::endl;
    std::mt19937 generator(time(0));
    std::uniform_real_distribution<> principal_dist(1000.0, 10000.0);
    std::uniform_real_distribution<> rate_dist(3.0, 8.0);
    std::uniform_int_distribution<> time_dist(1, 10);
    
    double principal = 9436.2;
    double rate = 5.4;
    int time_years = 3;

    std::cout << std::fixed << std::setprecision(2);
    std::cout << "Principal Amount: $" << principal << std::endl;
    std::cout << "Annual Interest Rate: " << rate << "%" << std::endl;
    std::cout << "Time Period: " << time_years << " years" << std::endl;

    double simple_interest = (principal * rate * time_years) / 100.0;
    
    std::cout << "Result: Simple Interest is $" << simple_interest << std::endl;
    
    return 0;
}