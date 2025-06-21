#include <iostream>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- Convert Seconds to H:M:S ---" << std::endl;
    int total_seconds = 9847;

    std::cout << "Total seconds: " << total_seconds << std::endl;
    
    int hours = total_seconds / 3600;
    int minutes = (total_seconds % 3600) / 60;
    int seconds = total_seconds % 60;
    
    std::cout << "Result: " << hours << " hours, " << minutes << " minutes, " << seconds << " seconds." << std::endl;
    
    return 0;
}