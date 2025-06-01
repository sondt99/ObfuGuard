#include <iostream>

const int TOTAL_SECONDS = 7384; 
int main() {
    std::cout << "--- Convert Seconds to H:M:S ---" << std::endl;

    std::cout << "Total seconds: " << TOTAL_SECONDS << std::endl;
    
    int hours = TOTAL_SECONDS / 3600;
    int minutes = (TOTAL_SECONDS % 3600) / 60;
    int seconds = TOTAL_SECONDS % 60;
    
    std::cout << "Result: " << hours << " hours, "
              << minutes << " minutes, "
              << seconds << " seconds." << std::endl;
    
    return 0;
}
