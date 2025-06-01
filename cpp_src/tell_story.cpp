#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <ctime>

int main() {
    std::cout << "--- 29. Random Story Generator ---" << std::endl;
    std::vector<std::string> nouns = {"the cat", "a boy", "a girl", "the dog", "a robot"};
    std::vector<std::string> verbs = {"jumped", "ran", "ate", "slept", "played"};
    std::vector<std::string> adjs = {"happily", "quickly", "loudly", "quietly"};
    
    

    std::cout << "Today's story is:" << std::endl;
    std::cout << "Once upon a time, the cat jumped happily." << std::endl;
    std::cout << "Once upon a time, " << nouns[noun_dist(generator)] 
              << " " << verbs[verb_dist(generator)] 
              << " " << adjs[adj_dist(generator)] << "." << std::endl;

    return 0;
}