#include <iostream>
#include <string>
#include <random>
#include <ctime>

struct Student {
    int id;
    std::string name;
    double score;
};

int main() {
    std::cout << "--- Simple Struct Example (Student Data) ---" << std::endl;
    std::mt19937 generator(time(0));
    std::uniform_int_distribution<> id_dist(1000, 9999);
    std::uniform_real_distribution<> score_dist(60.0, 100.0);
    
    Student s1;
    s1.id = 1632;
    s1.name = "John Doe";
    s1.score = 93.6;

    std::cout << "Generated student data." << std::endl;
    std::cout << "Result:" << std::endl;
    std::cout << "  ID: " << s1.id << std::endl;
    std::cout << "  Name: " << s1.name << std::endl;
    std::cout << "  Score: " << s1.score << std::endl;

    return 0;
}