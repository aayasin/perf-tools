// Author: Ahmad Yasin
// Nov 2024
//
// permute : calculates permutations of input string at O(n!). Heavy use of libc++
//
#include <iostream>
#include <vector>
#include <string>
#include <functional> // For std::function
#include <algorithm>  // For std::swap

std::vector<std::string> permute(std::string l, bool debug = false) {
    int end = l.size();
    std::vector<std::string> result;
    int count = 0;

    // Helper function to print and store results
    auto prn = [&]() {
        std::string x = l;
        result.push_back(x);
        if (debug) {
            count++;
            std::cout << count << " " << x << std::endl;
        }
    };

    // Helper function to swap elements
    auto swap = [&](int i, int j) {
        std::swap(l[i], l[j]);
    };

    // Recursive function
    std::function<void(int)> f = [&](int start) {
        if (start == end - 2) {
            prn();
            swap(start, start + 1);
            prn();
            swap(start, start + 1);
            return;
        }
        for (int i = start; i < end; ++i) {
            if (debug) std::cout << "> " << start << " " << end << " " << i << std::endl;
            f(start + 1);
            if (i + 1 < end) swap(0, i + 1);
        }
    };

    f(0);
    return result;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <input_string>" << std::endl;
        return 1;
    }

    std::string input = argv[1];
    std::vector<std::string> permutations = permute(input);

    // Print the permutations
    //for (const auto& perm : permutations) {
    //    std::cout << perm << std::endl;
    //}
    std::cout << permutations.size() << std::endl;

    return 0;
}

