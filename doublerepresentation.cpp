#include <iostream>
#include <climits>
#include <string>
#include <stdlib.h>
#include <math.h>

using namespace std;

int main(int argc, char* argv[])
{
    // double v = atof(argv[1].c_str());
    double v = 72.4;
    double bits[sizeof(double) * CHAR_BIT]; 
    // Boilerplate to circumvent the fact bitwise operators can't be applied to double
    union {
    double value;
    char   array[sizeof(double)];
    };

    value = v;

    for (int i = 0; i < sizeof(double) * CHAR_BIT; ++i) {
        // counter++;
        int relativeToByte = i % CHAR_BIT;
        bool isBitSet = (array[sizeof(double) - 1 - i / CHAR_BIT] & 
            (1 << (CHAR_BIT - relativeToByte - 1))) == (1 << (CHAR_BIT - relativeToByte - 1));
        // std::cout << (isBitSet ? "1" : "0");
        if (isBitSet){
            bits[i] = 1;
        }
        else{
            bits[i] = 0;
        }
    }

    for (int i = 0; i < sizeof(double) * CHAR_BIT; ++i) {
        cout << bits[i];
    }

    cout << "" << endl;

    double recalculated = 0;

    double temp = 1;
    for (int i=12; i < sizeof(double) * CHAR_BIT; i++){
        temp = temp + bits[i] * pow(2, -(i - 11));
    }
    double exponent;
    for (int i=11; i> 0; i--){
        exponent = exponent + bits[i] * pow(2, (11-i));
    }
    recalculated = temp * pow(2,(exponent - 1023));
    recalculated = recalculated * pow((-1), bits[0]);

    cout << "recalculated = " << recalculated << endl;  

    return 0;
}