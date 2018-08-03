#include <iostream>
#include <climits>
#include <string>
#include <stdlib.h>
#include <math.h>
#include <algorithm>

using namespace std;

// Function to convert decimal to binary upto
// k-precision after decimal point
string decimalToBinary(double num, int k_prec)
{
    string binary = "";
 
    // Fetch the integral part of decimal number
    int Integral = num;
 
    // Fetch the fractional part decimal number
    double fractional = num - Integral;
 
    // Conversion of integral part to
    // binary equivalent
    while (Integral)
    {
        int rem = Integral % 2;
 
        // Append 0 in binary
        binary.push_back(rem +'0');
 
        Integral /= 2;
    }
 
    // Reverse string to get original binary
    // equivalent
    reverse(binary.begin(),binary.end());
 
    // Append point before conversion of
    // fractional part
    binary.push_back('.');
 
    // Conversion of fractional part to
    // binary equivalent
    while (k_prec--)
    {
        // Find next bit in fraction
        fractional *= 2;
        int fract_bit = fractional;
 
        if (fract_bit == 1)
        {
            fractional -= fract_bit;
            binary.push_back(1 + '0');
        }
        else
            binary.push_back(0 + '0');
    }
 
    return binary;
}

int main(int argc, char* argv[])
{
    // // double v = atof(argv[1].c_str());
    // double v = 72.4;
    // double bits[sizeof(double) * CHAR_BIT]; 
    // // Boilerplate to circumvent the fact bitwise operators can't be applied to double
    // union {
    // double value;
    // char   array[sizeof(double)];
    // };

    // value = v;

    // for (int i = 0; i < sizeof(double) * CHAR_BIT; ++i) {
    //     // counter++;
    //     int relativeToByte = i % CHAR_BIT;
    //     bool isBitSet = (array[sizeof(double) - 1 - i / CHAR_BIT] & 
    //         (1 << (CHAR_BIT - relativeToByte - 1))) == (1 << (CHAR_BIT - relativeToByte - 1));
    //     // std::cout << (isBitSet ? "1" : "0");
    //     if (isBitSet){
    //         bits[i] = 1;
    //     }
    //     else{
    //         bits[i] = 0;
    //     }
    // }

    // for (int i = 0; i < sizeof(double) * CHAR_BIT; ++i) {
    //     cout << bits[i];
    // }

    // cout << "" << endl;

    // double recalculated = 0;

    // double temp = 1;
    // for (int i=12; i < sizeof(double) * CHAR_BIT; i++){
    //     temp = temp + bits[i] * pow(2, -(i - 11));
    // }
    // double exponent;
    // for (int i=11; i> 0; i--){
    //     exponent = exponent + bits[i] * pow(2, (11-i));
    // }
    // recalculated = temp * pow(2,(exponent - 1023));
    // recalculated = recalculated * pow((-1), bits[0]);

    // cout << "recalculated = " << recalculated << endl;  

    double n = 4.47;
    int k = 10;
    cout << decimalToBinary(n, k) << "\n";
 
    n = 6.986 , k = 5;
    cout << decimalToBinary(n, k);


    return 0;
}