#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <cstdlib>
#include <cassert>
#include <time.h>

#define null 0


using namespace std;



int main(int argc, char *argv[])
{
    string line;
    
    
    for (int i=0; i<16; i++) {
        cout << "i = " << i << endl;
        ifstream inputfile ("/home/taeyun/Desktop/mysqlproxy/datatobedecrypted" + to_string(i) + ".txt");
        // std::cout << "printing " << i << "th ciphertext" << std::endl;
        for (int j=0; j<500; j++){
            cout << "j = " << j << endl;
            // std::cout << "j = " << j << std::endl;
            // std::cout << "*ciphertext1[" << i << "]->a = " << *(ciphertext1[i].a + sizeof(Torus32) * j) <<std::endl;
            // *(answer[i].a + sizeof(answer[i].a) * j) = *(ciphertext1[i].a + sizeof(ciphertext1[i].a) * j);
            getline(inputfile, line);
            cout << line << endl;
            stoi(line);
        
        }
        // std::cout << "ciphertext1[" << i << "]->b = " << ciphertext1[i].b << std::endl;
        // std::cout << "ciphertext1[" << i << "]->current_variance = " << ciphertext1[i].current_variance << std::endl;
        // *answer[i].a = *ciphertext1[i].a;
        getline(inputfile, line);
        cout << line << endl;
        stoi(line);
        getline(inputfile, line);
        cout << line << endl;
        stod(line);
        inputfile.close();
    }
    

    // line = "1630361893";
    // line = "-1630361893";
    
    // stoi(line);

}