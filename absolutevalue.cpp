#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <iostream>
#include <bitset>


using namespace std;

int main(int argc, char *argv[]){
    if(argc!=2)
	{
		exit(0);
	}
	int v = atoi(argv[1]);  // we want to find the absolute value of v
    std::bitset<32> x(v);
    cout << "initial v = "<< x << endl;
    unsigned int r;  // the result goes here 
    // int const mask = v >> sizeof(int) * CHAR_BIT - 1;
    // cout << "sizeof(int) = " << sizeof(int) << endl;
    // int w = v >> sizeof(int) * 8;
    // std::bitset<32> y(w);
    // cout << "v >> sizeof(int) * 8 = " << y << endl;
    int const mask = v >> sizeof(int) * 8 - 1;
    cout << "mask = " << mask << endl;

    r = (v + mask) ^ mask;

    // Patented variation:

    // r = (v ^ mask) - mask;
    cout << "r = " << r << endl;
}