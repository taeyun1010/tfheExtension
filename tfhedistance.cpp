#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <cstdlib>
#include <cmath>
#include <sys/time.h>
#include <tfhe/tfhe.h>
#include <tfhe/polynomials.h>
#include <tfhe/lwesamples.h>
#include <tfhe/lwekey.h>
#include <tfhe/lweparams.h>
#include <tfhe/tlwe.h>
#include <tfhe/tgsw.h>
#include "tfhedistance.h"
#include <ctime>
#include <thread>
#include <future>
#include <list>
#include <deque>

using namespace std;

// int32_t numberofbits = 32;


//TODO: fix the assumption that integerbitsize and fractionbitsize are the same
//TODO: fix the assumption that numberofbits must be = integerbitsize + fractionbitsize when operating on Double
int32_t numberofbits = 32;

// these are number of bits used for representing Double struct
int integerbitsize = 0;
int fractionbitsize = 0;

//TODO: deallocate created Doubles
struct Double{
	LweSample *integerpart;
	LweSample *fractionpart;
};

// struct to be used in threaded multiplicator
struct multiplicator_data{
    LweSample *product; 
    LweSample *x; 
    LweSample *y; 
    int32_t nb_bits;
    const TFheGateBootstrappingCloudKeySet *bk; 
    const LweParams *in_out_params; 
    TFheGateBootstrappingSecretKeySet* key;
    int i;
};

// struct CipherSet{
// 	LweSample *a;
// 	LweSample *b;
// 	int minbit;
// 	const TFheGateBootstrappingCloudKeySet* EK;
// };
// struct MulInitSet{
// 	LweSample *C;
// 	LweSample *a;
// 	LweSample *b;
// 	int ind;
// 	const TFheGateBootstrappingCloudKeySet* EK;
// };
// struct CalcSet{
// 	LweSample *r;
// 	LweSample *a;
// 	LweSample *b;
// 	LweSample *c;
// 	const TFheGateBootstrappingCloudKeySet* EK;
// };

// **********************************************************************************
// ********************************* MAIN *******************************************
// **********************************************************************************


void dieDramatically(string message) {
    cerr << message << endl;
    abort();
}

// //encrypts given integer part of Double
// // ciphertext[0] holds least significant bit
// // ciphertext[integerbitsize-1] holds the most significant bit 
// LweSample* encryptIntegerpart(int plaintext, TFheGateBootstrappingSecretKeySet* key){
// 	LweSample *ciphertext = new_gate_bootstrapping_ciphertext_array(integerbitsize,key->params);
	
// 	for(int i=0;i<integerbitsize;i++)
// 	{
// 		bootsSymEncrypt(&ciphertext[integerbitsize-1-i],(plaintext>>i)&0x01,key);
		
// 		// //
// 		// int temp = bootsSymDecrypt(&ciphertext[integerbitsize-1-i], key);
// 		// cout << "integerpart[" << i << "] = " << temp << endl;
// 		// //
// 	}
// 	return ciphertext;
// }




// //when plaintext is given in double type   i.e. 0.xxx
// //encrypts given fractional part, where argument plaintext is given as 41 if integer was 124.41
// LweSample* encryptFractionpart(double plaintext, TFheGateBootstrappingSecretKeySet* key){
//     // plaintext = fabs(plaintext);

// 	LweSample *ciphertext = new_gate_bootstrapping_ciphertext_array(fractionbitsize,key->params);
// 	// int numdigitsbefore, numdigitsafter;
// 	for(int i=0;i<fractionbitsize;i++)
// 	{
// 		// cout << "plaintext = " << plaintext << endl;
// 		// numdigitsbefore = numDigits(plaintext);
// 		plaintext = plaintext * 2;
// 		// numdigitsafter = numDigits(plaintext);
// 		if (plaintext >= 1){
// 			// bootsSymEncrypt(&ciphertext[fractionbitsize-1-i],1,key);
// 			bootsSymEncrypt(&ciphertext[i],1,key);
			
// 			// //
// 			// int temp = bootsSymDecrypt(&ciphertext[i], key);
// 			// cout << "fractionpart[" << i << "] = " << temp << endl;
// 			// //
			
// 			//get rid of the leading 1
// 			plaintext = plaintext - 1;
// 		}
// 		else {
// 			// bootsSymEncrypt(&ciphertext[fractionbitsize-1-i],0,key);
// 			bootsSymEncrypt(&ciphertext[i],0,key);
		
// 			// //
// 			// int temp = bootsSymDecrypt(&ciphertext[i], key);
// 			// cout << "fractionpart[" << i << "] = " << temp << endl;
// 			// //
		
// 		}
// 		// bootsSymEncrypt(&ciphertext[fractionbitsize-1-i],(plaintext>>i)&0x01,key);
// 	}
// 	return ciphertext;
// }

//encrypts given integer part of Double
// ciphertext[0] holds least significant bit
// ciphertext[integerbitsize-1] holds the most significant bit 
LweSample* encryptIntegerpart(int plaintext, TFheGateBootstrappingSecretKeySet* key){
	LweSample *ciphertext = new_gate_bootstrapping_ciphertext_array(integerbitsize,key->params);
	
	for(int i=0;i<integerbitsize;i++)
	{
		bootsSymEncrypt(&ciphertext[i],(plaintext>>i)&0x01,key);
		
		// //
		// int temp = bootsSymDecrypt(&ciphertext[integerbitsize-1-i], key);
		// cout << "integerpart[" << i << "] = " << temp << endl;
		// //
	}
	return ciphertext;
}




//when plaintext is given in double type   i.e. 0.xxx
//encrypts given fractional part, where argument plaintext is given as 41 if integer was 124.41
LweSample* encryptFractionpart(double plaintext, TFheGateBootstrappingSecretKeySet* key){
    // plaintext = fabs(plaintext);

	LweSample *ciphertext = new_gate_bootstrapping_ciphertext_array(fractionbitsize,key->params);
	// int numdigitsbefore, numdigitsafter;
	for(int i=fractionbitsize-1;i>=0;i--)
	{
		// cout << "plaintext = " << plaintext << endl;
		// numdigitsbefore = numDigits(plaintext);
		plaintext = plaintext * 2;
		// numdigitsafter = numDigits(plaintext);
		if (plaintext >= 1){
			// bootsSymEncrypt(&ciphertext[fractionbitsize-1-i],1,key);
			bootsSymEncrypt(&ciphertext[i],1,key);
			
			// //
			// int temp = bootsSymDecrypt(&ciphertext[i], key);
			// cout << "fractionpart[" << i << "] = " << temp << endl;
			// //
			
			//get rid of the leading 1
			plaintext = plaintext - 1;
		}
		else {
			// bootsSymEncrypt(&ciphertext[fractionbitsize-1-i],0,key);
			bootsSymEncrypt(&ciphertext[i],0,key);
		
			// //
			// int temp = bootsSymDecrypt(&ciphertext[i], key);
			// cout << "fractionpart[" << i << "] = " << temp << endl;
			// //
		
		}
		// bootsSymEncrypt(&ciphertext[fractionbitsize-1-i],(plaintext>>i)&0x01,key);
	}
	return ciphertext;
}

// // decrypts given integer part of Double struct
// int decryptIntegerpart(LweSample* input, TFheGateBootstrappingSecretKeySet* key){
// 	int Result = 0;
// 	for(int i=0;i<integerbitsize;i++)
// 	{
// 		// //
// 		// int intermediateBit = bootsSymDecrypt(&input[i],key);
// 		// cout << "intermediateBit = " << intermediateBit << endl;
// 		// //
		
// 		Result<<=1;
// 		Result+=bootsSymDecrypt(&input[i],key);
// 	}	
// 	return Result;
// }

// // decrypts given fractional part of Double struct
// double decryptFractionpart(LweSample* input, TFheGateBootstrappingSecretKeySet* key){
// 	double result = 0;
// 	for(int i=0;i<fractionbitsize;i++)
// 	{
// 		int temp = bootsSymDecrypt(&input[i],key);
// 		cout << "temp[" << i << "] = " << temp << endl;
// 		result += temp * (pow(2, -(i+1)));
// 	}	
// 	return result;
// }

// decrypts given integer part of Double struct
int decryptIntegerpart(LweSample* input, TFheGateBootstrappingSecretKeySet* key){
    //decrypt and rebuild the 32-bit plaintext answer
    int int_answer = 0;
    for (int i=0; i<integerbitsize; i++) {
        int ai = bootsSymDecrypt(&input[i], key);
        int_answer |= (ai<<i);
    }
    // cout << "int_answer = " << int_answer << endl;
	return int_answer;
}

// decrypts given fractional part of Double struct
double decryptFractionpart(LweSample* input, TFheGateBootstrappingSecretKeySet* key){
	double result = 0;
    int counter = -1;
	for(int i=fractionbitsize-1;i>=0;i--)
	{
		int temp = bootsSymDecrypt(&input[i],key);
		cout << "temp[" << i << "] = " << temp << endl;
		result += temp * (pow(2, counter));
        counter--;
	}	
	return result;
}

// decrypts given Double struct
double decryptDouble(Double d, TFheGateBootstrappingSecretKeySet* key){
	double result;
	LweSample* integerpart = d.integerpart;
	LweSample* fractionpart = d.fractionpart;

    // cout << "start of integerpart" << endl;
    // for(int i=0 ; i < integerbitsize; i++){
    //     int temp = bootsSymDecrypt(&integerpart[i],key);
	// 	cout << "temp[" << i << "] = " << temp << endl;
    // }
    // cout << "end of integerpart" << endl;


    // cout << "start of fractionpart" << endl;
    // for(int i=0 ; i < integerbitsize; i++){
    //     int temp = bootsSymDecrypt(&fractionpart[i],key);
	// 	cout << "temp[" << i << "] = " << temp << endl;
    // }
    // cout << "end of fractionpart" << endl;

    //
    // //decrypt and rebuild the 32-bit plaintext answer
    // int32_t int_answer = 0;
    // for (int i=0; i<integerbitsize; i++) {
    //     int ai = bootsSymDecrypt(&integerpart[i], key);
    //     int_answer |= (ai<<i);
    // }
    // cout << "int_answer = " << int_answer << endl;
    //

	int decryptedintpart = decryptIntegerpart(integerpart, key);
	// cout << "decryptedintpart = " << decryptedintpart << endl;
	double decryptedfracpart = decryptFractionpart(fractionpart, key);
	// cout << "decryptedfracpart = " << decryptedfracpart << endl;

    // //if the plaintext value is going to be negative
    // if (decryptedintpart < 0){
    //     result = decryptedintpart + decryptedfracpart;
    // }
    // else{
	//     result = decryptedintpart + decryptedfracpart;
    // }


    result = decryptedintpart + decryptedfracpart;

    return result;
}

// //prints the bit representation of a given double, in double precision format, including mantissa and etc..
// void printdoublebits(double doubleValue){
//     cout << "inside printdoublebits function" << endl;
//     uint8_t *bytePointer = (uint8_t *)&doubleValue;

//     for(size_t index = 0; index < sizeof(double); index++)
//     {
//         uint8_t byte = bytePointer[index];

//         for(int bit = 0; bit < 8; bit++)
//         {
//             printf("%d", byte&1);
//             byte >>= 1;
//         }
//     }
//     cout << "leaving printdoublebits function" << endl;
// }

//given double, encrypts it to Double
Double encryptDouble(double plaintext, TFheGateBootstrappingSecretKeySet* key){
    Double result;

    //fraction part first, then integerpart, from least significant to most significant
    // for instance, 00100101 for -5.75 using 4 bits for decimal and 4 bits for fraction parts
    int bitholder[(integerbitsize + fractionbitsize)];
    double integral;
    int integralint;
    double fractional = modf(plaintext, &integral);
    integralint = integral;
    LweSample *integerpart = new_gate_bootstrapping_ciphertext_array(integerbitsize,key->params);
    LweSample *fractionpart = new_gate_bootstrapping_ciphertext_array(fractionbitsize,key->params);
    //if plaintext is positive 
    if(plaintext >= 0){
        integerpart = encryptIntegerpart(integralint, key);
        // fractionpart = encryptFractionpart(128, key);
        fractionpart = encryptFractionpart(fractional, key);
        // int result = decryptIntegerpart(integerpart, key);
        // cout << "integerpart decrypted result = " << result << endl;
        // int result = decryptIntegerpart(integerpart1, key);
        // cout << "integerpart decrypted result = " << result << endl;
        // double fractionresult = decryptFractionpart(fractionpart1, key);
        // cout << "fractionpart1 decrypted result = " << fractionresult << endl;
        
    }

    //if plaintext is negative, https://stackoverflow.com/questions/42439749/how-to-convert-negative-fraction-decimal-to-binary to calculate bits of negative double
    else {
        integralint = (-1) * integralint;
        fractional = (-1) * fractional;
        for(int i=0;i<integerbitsize;i++)
        {
            bitholder[fractionbitsize+i] = (integralint>>i)&0x01;


            // bootsSymEncrypt(&ciphertext[integerbitsize-1-i],(plaintext>>i)&0x01,key);
            
            // //
            // int temp = bootsSymDecrypt(&ciphertext[integerbitsize-1-i], key);
            // cout << "integerpart[" << i << "] = " << temp << endl;
            // //
        }
        for(int i=(fractionbitsize-1);i>=0;i--)
        {
            // cout << "plaintext = " << plaintext << endl;
            // numdigitsbefore = numDigits(plaintext);
            fractional = fractional * 2;
            // numdigitsafter = numDigits(plaintext);
            if (fractional >= 1){
                // bootsSymEncrypt(&ciphertext[fractionbitsize-1-i],1,key);
                // bootsSymEncrypt(&ciphertext[i],1,key);
                bitholder[i] = 1;
                // //
                // int temp = bootsSymDecrypt(&ciphertext[i], key);
                // cout << "fractionpart[" << i << "] = " << temp << endl;
                // //
                
                //get rid of the leading 1
                fractional = fractional - 1;
            }
            else {
                // bootsSymEncrypt(&ciphertext[fractionbitsize-1-i],0,key);
                // bootsSymEncrypt(&ciphertext[i],0,key);
                bitholder[i] = 0;

                // //
                // int temp = bootsSymDecrypt(&ciphertext[i], key);
                // cout << "fractionpart[" << i << "] = " << temp << endl;
                // //
            
            }
            // bootsSymEncrypt(&ciphertext[fractionbitsize-1-i],(fractional>>i)&0x01,key);
        }


        // for (int i=0; i<(integerbitsize+fractionbitsize);i++){
        //     cout << "bitholder[" << i << "] = " << bitholder[i] << endl;
        // }

        //bits of positive representation has been calculated, invert all bits
        for (int i=0; i<(integerbitsize+fractionbitsize);i++){
            if (bitholder[i] == 1){
                bitholder[i] = 0;
            }
            else{
                bitholder[i] = 1;
            }
        }

        // cout <<"done with inverting " << endl;
        // for (int i=0; i<(integerbitsize+fractionbitsize);i++){
        //     cout << "bitholder[" << i << "] = " << bitholder[i] << endl;
        // }

        //add 1 to the least significant digit
        int carry = 1;
        for (int i=0; i<(integerbitsize+fractionbitsize);i++){
            switch (bitholder[i] + carry){
                case 2:{
                    bitholder[i] = 0;
                    carry = 1;  
                    break;
                }
                case 1:{
                    bitholder[i] = 1;
                    carry = 0;
                    break;
                }
                case 0:{
                    bitholder[i] = 0;
                    carry = 0;
                    break;
                }
            }
        }

        cout <<"done with addition of 1" << endl;
        for (int i=0; i<(integerbitsize+fractionbitsize);i++){
            cout << "bitholder[" << i << "] = " << bitholder[i] << endl;
        }

        //bitholder now has bits for negative double values, must encrypt
        for(int i=0;i<integerbitsize;i++)
        {
            bootsSymEncrypt(&integerpart[i],bitholder[fractionbitsize+i],key);
            
            // //
            // int temp = bootsSymDecrypt(&ciphertext[integerbitsize-1-i], key);
            // cout << "integerpart[" << i << "] = " << temp << endl;
            // //
        }
        for(int i=0;i<fractionbitsize;i++)
        {
            bootsSymEncrypt(&fractionpart[i],bitholder[i],key);
            
            // //
            // int temp = bootsSymDecrypt(&ciphertext[integerbitsize-1-i], key);
            // cout << "integerpart[" << i << "] = " << temp << endl;
            // //
        }


    }
    result.integerpart = integerpart;
    result.fractionpart = fractionpart;
    return result;

    
}

// //given double, encrypts it to Double
// Double encryptDouble(double plaintext, TFheGateBootstrappingSecretKeySet* key){
//     Double result;

    
//     int bitholder[(integerbitsize + fractionbitsize)];
//     double integral;
//     int integralint;
//     double fractional = modf(plaintext, &integral);
//     integralint = integral;
//     LweSample *integerpart = new_gate_bootstrapping_ciphertext_array(integerbitsize,key->params);
//     LweSample *fractionpart = new_gate_bootstrapping_ciphertext_array(fractionbitsize,key->params);
//     //if plaintext is positive 
//     if(plaintext >= 0){
//         integerpart = encryptIntegerpart(integralint, key);
//         // fractionpart = encryptFractionpart(128, key);
//         fractionpart = encryptFractionpart(fractional, key);
//         // int result = decryptIntegerpart(integerpart, key);
//         // cout << "integerpart decrypted result = " << result << endl;
//         // int result = decryptIntegerpart(integerpart1, key);
//         // cout << "integerpart decrypted result = " << result << endl;
//         // double fractionresult = decryptFractionpart(fractionpart1, key);
//         // cout << "fractionpart1 decrypted result = " << fractionresult << endl;
        
//     }

//     //if plaintext is negative, https://stackoverflow.com/questions/42439749/how-to-convert-negative-fraction-decimal-to-binary to calculate bits of negative double
//     //integer part first, then fractionpart, from most significant to least significant
//     // for instance, 00100101 for -5.75 using 4 bits for decimal and 4 bits for fraction parts
//     else {
//         integralint = (-1) * integralint;
//         fractional = (-1) * fractional;
//         for(int i=integerbitsize-1;i>=0;i--)
//         {
//             bitholder[i] = (integralint>>i)&0x01;


//             // bootsSymEncrypt(&ciphertext[integerbitsize-1-i],(plaintext>>i)&0x01,key);
            
//             // //
//             // int temp = bootsSymDecrypt(&ciphertext[integerbitsize-1-i], key);
//             // cout << "integerpart[" << i << "] = " << temp << endl;
//             // //
//         }
//         for(int i=fractionbitsize;i < (integerbitsize+fractionbitsize);i++)
//         {
//             // cout << "plaintext = " << plaintext << endl;
//             // numdigitsbefore = numDigits(plaintext);
//             fractional = fractional * 2;
//             // numdigitsafter = numDigits(plaintext);
//             if (fractional >= 1){
//                 // bootsSymEncrypt(&ciphertext[fractionbitsize-1-i],1,key);
//                 // bootsSymEncrypt(&ciphertext[i],1,key);
//                 bitholder[i] = 1;
//                 // //
//                 // int temp = bootsSymDecrypt(&ciphertext[i], key);
//                 // cout << "fractionpart[" << i << "] = " << temp << endl;
//                 // //
                
//                 //get rid of the leading 1
//                 fractional = fractional - 1;
//             }
//             else {
//                 // bootsSymEncrypt(&ciphertext[fractionbitsize-1-i],0,key);
//                 // bootsSymEncrypt(&ciphertext[i],0,key);
//                 bitholder[i] = 0;

//                 // //
//                 // int temp = bootsSymDecrypt(&ciphertext[i], key);
//                 // cout << "fractionpart[" << i << "] = " << temp << endl;
//                 // //
            
//             }
//             // bootsSymEncrypt(&ciphertext[fractionbitsize-1-i],(fractional>>i)&0x01,key);
//         }


//         for (int i=0; i<(integerbitsize+fractionbitsize);i++){
//             cout << "bitholder[" << i << "] = " << bitholder[i] << endl;
//         }

//         //bits of positive representation has been calculated, invert all bits
//         for (int i=0; i<(integerbitsize+fractionbitsize);i++){
//             if (bitholder[i] == 1){
//                 bitholder[i] = 0;
//             }
//             else{
//                 bitholder[i] = 1;
//             }
//         }

//         cout <<"done with inverting " << endl;
//         for (int i=0; i<(integerbitsize+fractionbitsize);i++){
//             cout << "bitholder[" << i << "] = " << bitholder[i] << endl;
//         }

//         //add 1 to the least significant digit
//         int carry = 1;
//         for (int i=0; i<(integerbitsize+fractionbitsize);i++){
//             switch (bitholder[i] + carry){
//                 case 2:{
//                     bitholder[i] = 0;
//                     carry = 1;  
//                     break;
//                 }
//                 case 1:{
//                     bitholder[i] = 1;
//                     carry = 0;
//                     break;
//                 }
//                 case 0:{
//                     bitholder[i] = 0;
//                     carry = 0;
//                     break;
//                 }
//             }
//         }

//         cout <<"done with addition of 1" << endl;
//         for (int i=0; i<(integerbitsize+fractionbitsize);i++){
//             cout << "bitholder[" << i << "] = " << bitholder[i] << endl;
//         }

//         //bitholder now has bits for negative double values, must encrypt
//         for(int i=0;i<integerbitsize;i++)
//         {
//             bootsSymEncrypt(&integerpart[i],bitholder[fractionbitsize+i],key);
            
//             // //
//             // int temp = bootsSymDecrypt(&ciphertext[integerbitsize-1-i], key);
//             // cout << "integerpart[" << i << "] = " << temp << endl;
//             // //
//         }
//         for(int i=0;i<fractionbitsize;i++)
//         {
//             bootsSymEncrypt(&fractionpart[i],bitholder[i],key);
            
//             // //
//             // int temp = bootsSymDecrypt(&ciphertext[integerbitsize-1-i], key);
//             // cout << "integerpart[" << i << "] = " << temp << endl;
//             // //
//         }


//     }
//     result.integerpart = integerpart;
//     result.fractionpart = fractionpart;
//     return result;

    
// }

// decrypts given LweSample
int32_t decryptLweSample(const LweSample* input, const int32_t nb_bits, TFheGateBootstrappingSecretKeySet* key){
	int32_t int_answer = 0;
    for (int i=0; i<nb_bits; i++) {
        int ai = bootsSymDecrypt(&input[i], key);
        cout << "decrypted ai = " << ai << endl;
        int_answer |= (ai<<i);
    }
    return int_answer;
}

void full_adder_MUX(LweSample *sum, const LweSample *x, const LweSample *y, const int32_t nb_bits,
                    const TFheGateBootstrappingSecretKeySet *keyset) {
    const LweParams *in_out_params = keyset->params->in_out_params;
    // carries
    LweSample *carry = new_LweSample_array(2, in_out_params);
    bootsSymEncrypt(carry, 0, keyset); // first carry initialized to 0
    // temps
    LweSample *temp = new_LweSample_array(2, in_out_params);

    for (int32_t i = 0; i < nb_bits; ++i) {
        int ai = bootsSymDecrypt(&x[i], keyset);
        cout << "decrypted x[" << i << "] = " << ai << endl;
        ai = bootsSymDecrypt(&y[i], keyset);
        cout << "decrypted y[" << i << "] = " << ai << endl;


        //sumi = xi XOR yi XOR carry(i-1) 
        bootsXOR(temp, x + i, y + i, &keyset->cloud); // temp = xi XOR yi

        ai = bootsSymDecrypt(temp, keyset);
        cout << "decrypted temp = " << ai << endl;
        
        bootsXOR(sum + i, temp, carry, &keyset->cloud);

        ai = bootsSymDecrypt(sum+i, keyset);
        cout << "decrypted sum = " << ai << endl;

        // carry = MUX(xi XOR yi, carry(i-1), xi AND yi)
        bootsAND(temp + 1, x + i, y + i, &keyset->cloud); // temp1 = xi AND yi
        bootsMUX(carry + 1, temp, carry, temp + 1, &keyset->cloud);

        ai = bootsSymDecrypt(carry+1, keyset);
        cout << "decrypted carry = " << ai << endl;

        bool mess1 = bootsSymDecrypt(temp, keyset);
        bool mess2 = bootsSymDecrypt(carry, keyset);
        bool mess3 = bootsSymDecrypt(temp + 1, keyset);
        bool messmux = bootsSymDecrypt(carry + 1, keyset);

        if (messmux != (mess1 ? mess2 : mess3)) {
            cout << "ERROR!!! " << i << " - ";
            cout << t32tod(lwePhase(temp, keyset->lwe_key)) << " - ";
            cout << t32tod(lwePhase(carry, keyset->lwe_key)) << " - ";
            cout << t32tod(lwePhase(temp + 1, keyset->lwe_key)) << " - ";
            cout << t32tod(lwePhase(carry + 1, keyset->lwe_key)) << endl;
        }

        bootsCOPY(carry, carry + 1, &keyset->cloud);
    }
    bootsCOPY(sum + nb_bits, carry, &keyset->cloud);

    delete_LweSample_array(2, temp);
    delete_LweSample_array(2, carry);
}

//TODO: delete key argument
void full_adder(LweSample *sum, const LweSample *x, const LweSample *y, const int32_t nb_bits,
                const TFheGateBootstrappingCloudKeySet *bk, const LweParams *in_out_params, TFheGateBootstrappingSecretKeySet* key) {
    // int decryptedx = decryptLweSample(x, nb_bits, key);
    // int decryptedy = decryptLweSample(y, nb_bits, key);
    
    // cout << "decryptedx = " << decryptedx << endl;
    // cout << "decryptedy = " << decryptedy << endl;

    // cout << "start of decrypted x for full_adder" <<endl;
    // for (int i=0; i<numberofbits; i++) {
    //     int ai = bootsSymDecrypt(&x[i], key);
    //     cout << "decrypted ai = " << ai << endl;
    // }
    // cout << "end of decrypted x for full_adder" <<endl;

    // cout << "start of decrypted y for full_adder" <<endl;
    // for (int i=0; i<numberofbits; i++) {
    //     int ai = bootsSymDecrypt(&y[i], key);
    //     cout << "decrypted ai = " << ai << endl;
    // }
    // cout << "end of decrypted y for full_adder" <<endl;

    // carries
    LweSample *carry = new_LweSample_array(2, in_out_params);
    // first carry initialized to 0
    bootsCONSTANT(carry, 0, bk);
    // temps
    LweSample *temp = new_LweSample_array(3, in_out_params);

    for (int32_t i = 0; i < nb_bits; ++i) {

        // int ai = bootsSymDecrypt(&x[i], key);
        // cout << "decrypted x[" << i << "] = " << ai << endl;
        // ai = bootsSymDecrypt(&y[i], key);
        // cout << "decrypted y[" << i << "] = " << ai << endl;
        

        //sumi = xi XOR yi XOR carry(i-1) 
        bootsXOR(temp, x + i, y + i, bk); // temp = xi XOR yi
        // ai = bootsSymDecrypt(carry, key);
        // cout << "decrypted carry = " << ai << endl;
        // ai = bootsSymDecrypt(temp, key);
        // cout << "decrypted temp = " << ai << endl;
        bootsXOR(sum + i, temp, carry, bk);

        
        // int decryptedbit = bootsSymDecrypt(sum + i, key);
        // cout << "sum[" << i << "] = " << decryptedbit << endl;
        


        // carry = (xi AND yi) XOR (carry(i-1) AND (xi XOR yi))
        bootsAND(temp + 1, x + i, y + i, bk); // temp1 = xi AND yi
        bootsAND(temp + 2, carry, temp, bk); // temp2 = carry AND temp
        bootsXOR(carry + 1, temp + 1, temp + 2, bk);

        // int decryptedcarry = bootsSymDecrypt(carry + 1, key);
        // cout << "carry[" << i << "] = " << decryptedcarry << endl;

        bootsCOPY(carry, carry + 1, bk);
    }
    bootsCOPY(sum + nb_bits, carry, bk);

    delete_LweSample_array(3, temp);
    delete_LweSample_array(2, carry);
}



// //TODO: delete key argument
// void full_adder_doublehelper(LweSample *sum, const LweSample *x, const LweSample *y, const int32_t nb_bits,
//                 const TFheGateBootstrappingCloudKeySet *bk, const LweParams *in_out_params, TFheGateBootstrappingSecretKeySet* key) {
//     // int decryptedx = decryptLweSample(x, nb_bits, key);
//     // int decryptedy = decryptLweSample(y, nb_bits, key);
    
//     // cout << "decryptedx = " << decryptedx << endl;
//     // cout << "decryptedy = " << decryptedy << endl;

//     for (int32_t i = 0; i < nb_bits; ++i) {
//         int ai = bootsSymDecrypt(&x[i], key);
//         cout << "decrypted x[" << i << "] = " << ai << endl;
//     }

//     for (int32_t i = 0; i < nb_bits; ++i) {
//         int bi = bootsSymDecrypt(&y[i], key);
//         cout << "decrypted y[" << i << "] = " << bi << endl;
//     }
   

//     // carries
//     LweSample *carry = new_LweSample_array(2, in_out_params);
//     // first carry initialized to 0
//     bootsCONSTANT(carry, 0, bk);
//     // temps
//     LweSample *temp = new_LweSample_array(3, in_out_params);

//     // for (int32_t i = (nb_bits-1); i >= 0; --i) {
//     for (int32_t i = 0; i < nb_bits; ++i) {
//         // int ai = bootsSymDecrypt(&x[i], key);
//         // cout << "decrypted x[" << i << "] = " << ai << endl;
//         // ai = bootsSymDecrypt(&y[i], key);
//         // cout << "decrypted y[" << i << "] = " << ai << endl;

//         //sumi = xi XOR yi XOR carry(i-1) 
//         bootsXOR(temp, x + i, y + i, bk); // temp = xi XOR yi
//         bootsXOR(sum + i, temp, carry, bk);

        
//         int decryptedbit = bootsSymDecrypt(sum + i, key);
//         cout << "sum[" << i << "] = " << decryptedbit << endl;
        


//         // carry = (xi AND yi) XOR (carry(i-1) AND (xi XOR yi))
//         bootsAND(temp + 1, x + i, y + i, bk); // temp1 = xi AND yi
//         bootsAND(temp + 2, carry, temp, bk); // temp2 = carry AND temp
//         bootsXOR(carry + 1, temp + 1, temp + 2, bk);
//         bootsCOPY(carry, carry + 1, bk);
//     }
//     bootsCOPY(sum + nb_bits, carry, bk);

//     delete_LweSample_array(3, temp);
//     delete_LweSample_array(2, carry);
// }

// //TODO: delete key argument
// Double full_adder_double(Double x, Double y, 
//                 const TFheGateBootstrappingCloudKeySet *bk, const LweParams *in_out_params, TFheGateBootstrappingSecretKeySet* key) {
//     Double result;
// 	LweSample* a = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,bk->params);
// 	LweSample* b = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,bk->params);

//     // carries
//     LweSample *carry = new_LweSample_array(2, in_out_params);

//     //
//     //
//     for (int i=0; i < integerbitsize; i++){
// 		bootsCOPY(&a[i],&x.integerpart[i],bk);
// 		bootsCOPY(&b[i],&y.integerpart[i],bk);
// 	}
// 	for (int i=integerbitsize; i < (integerbitsize + fractionbitsize); i++){
// 		bootsCOPY(&a[i],&x.fractionpart[i-integerbitsize],bk);
// 		bootsCOPY(&b[i],&y.fractionpart[i-integerbitsize],bk);

// 		// //
// 		// int decryptedbit = bootsSymDecrypt(&a[i],key);
// 		// cout << "decryptedbit[" << i << "] = " << decryptedbit << endl;
// 		// //

// 		// bootsCOPY(&c[i],&input1.fractionpart[i-integerbitsize],bk);
// 		// bootsCOPY(&d[i],&input2.fractionpart[i-integerbitsize],bk);

// 	}
//     //
//     //


//     //
//     //
//     // for (int i=0; i < fractionbitsize; i++){
// 	// 	bootsCOPY(&a[i],&x.fractionpart[i],bk);
// 	// 	bootsCOPY(&b[i],&y.fractionpart[i],bk);
// 	// }
// 	// for (int i=fractionbitsize; i < (integerbitsize + fractionbitsize); i++){
// 	// 	bootsCOPY(&a[i],&x.integerpart[i-fractionbitsize],bk);
// 	// 	bootsCOPY(&b[i],&y.integerpart[i-fractionbitsize],bk);

// 	// 	// //
// 	// 	// int decryptedbit = bootsSymDecrypt(&a[i],key);
// 	// 	// cout << "decryptedbit[" << i << "] = " << decryptedbit << endl;
// 	// 	// //

// 	// 	// bootsCOPY(&c[i],&input1.fractionpart[i-integerbitsize],bk);
// 	// 	// bootsCOPY(&d[i],&input2.fractionpart[i-integerbitsize],bk);

// 	// }
//     //
//     //



// 	double decryptedfraction = decryptFractionpart(&a[integerbitsize], key);
// 	cout << "decryptedfraction = " << decryptedfraction << endl;
// 	double decryptedfraction2 = decryptFractionpart(&b[integerbitsize], key);
// 	cout << "decryptedfraction2 = " << decryptedfraction2 << endl;
// 	int decryptedinteger1 = decryptIntegerpart(&a[0], key);
//     cout << "decryptedinteger1 = " << decryptedinteger1 << endl;
// 	double decryptedinteger2 = decryptIntegerpart(&b[0], key);
// 	cout << "decryptedinteger2 = " << decryptedinteger2 << endl;
    
    
//     // //
// 	// for (int i=0; i < fractionbitsize; i++){
// 	// 	bootsCOPY(&c[i],&input1.fractionpart[i],bk);
// 	// 	bootsCOPY(&d[i],&input2.fractionpart[i],bk);

// 	// }
// 	// //


// 	LweSample *sum = new_gate_bootstrapping_ciphertext_array(numberofbits + 1,bk->params);

//     full_adder_doublehelper(sum, a, b, integerbitsize + fractionbitsize, bk, in_out_params, key);

//     result.integerpart = sum;
// 	result.fractionpart = sum + integerbitsize; 

//     //TODO: deallocate a and b?

//     return result;

// }

//TODO: delete key argument
Double full_adder_double(Double x, Double y, 
                const TFheGateBootstrappingCloudKeySet *bk, const LweParams *in_out_params, TFheGateBootstrappingSecretKeySet* key) {
    Double result;
	LweSample* a = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,bk->params);
	LweSample* b = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,bk->params);

    // carries
    LweSample *carry = new_LweSample_array(2, in_out_params);

    // //
    // //
    // for (int i=0; i < integerbitsize; i++){
	// 	bootsCOPY(&a[i],&x.integerpart[i],bk);
	// 	bootsCOPY(&b[i],&y.integerpart[i],bk);
	// }
	// for (int i=integerbitsize; i < (integerbitsize + fractionbitsize); i++){
	// 	bootsCOPY(&a[i],&x.fractionpart[i-integerbitsize],bk);
	// 	bootsCOPY(&b[i],&y.fractionpart[i-integerbitsize],bk);

	// 	// //
	// 	// int decryptedbit = bootsSymDecrypt(&a[i],key);
	// 	// cout << "decryptedbit[" << i << "] = " << decryptedbit << endl;
	// 	// //

	// 	// bootsCOPY(&c[i],&input1.fractionpart[i-integerbitsize],bk);
	// 	// bootsCOPY(&d[i],&input2.fractionpart[i-integerbitsize],bk);

	// }
    // //
    // //


    //
    //
    for (int i=0; i < fractionbitsize; i++){
		bootsCOPY(&a[i],&x.fractionpart[i],bk);
		bootsCOPY(&b[i],&y.fractionpart[i],bk);
	}
	for (int i=fractionbitsize; i < (integerbitsize + fractionbitsize); i++){
		bootsCOPY(&a[i],&x.integerpart[i-fractionbitsize],bk);
		bootsCOPY(&b[i],&y.integerpart[i-fractionbitsize],bk);

		// //
		// int decryptedbit = bootsSymDecrypt(&a[i],key);
		// cout << "decryptedbit[" << i << "] = " << decryptedbit << endl;
		// //

		// bootsCOPY(&c[i],&input1.fractionpart[i-integerbitsize],bk);
		// bootsCOPY(&d[i],&input2.fractionpart[i-integerbitsize],bk);

	}
    //
    //



	// double decryptedfraction = decryptFractionpart(&a[0], key);
	// cout << "decryptedfraction = " << decryptedfraction << endl;
	// double decryptedfraction2 = decryptFractionpart(&b[0], key);
	// cout << "decryptedfraction2 = " << decryptedfraction2 << endl;
	// int decryptedinteger1 = decryptIntegerpart(&a[fractionbitsize], key);
    // cout << "decryptedinteger1 = " << decryptedinteger1 << endl;
	// double decryptedinteger2 = decryptIntegerpart(&b[fractionbitsize], key);
	// cout << "decryptedinteger2 = " << decryptedinteger2 << endl;
    
    
    // //
	// for (int i=0; i < fractionbitsize; i++){
	// 	bootsCOPY(&c[i],&input1.fractionpart[i],bk);
	// 	bootsCOPY(&d[i],&input2.fractionpart[i],bk);

	// }
	// //


	LweSample *sum = new_gate_bootstrapping_ciphertext_array(numberofbits + 1,bk->params);

    // full_adder_doublehelper(sum, a, b, integerbitsize + fractionbitsize, bk, in_out_params, key);
    
    
    full_adder(sum, a, b, integerbitsize + fractionbitsize, bk, in_out_params, key);
    // full_adder_MUX(sum, a, b, integerbitsize + fractionbitsize, key);


    // cout << "start of decrypted sum" <<endl;
    // for (int i=0; i<numberofbits; i++) {
    //     int ai = bootsSymDecrypt(&sum[i], key);
    //     cout << "decrypted ai = " << ai << endl;
    // }
    // cout << "end of decrypted sum" <<endl;

    result.integerpart = sum + fractionbitsize;
	result.fractionpart = sum; 

    //TODO: deallocate a and b?

    return result;

}

// //TODO: delete key argument
// Double full_adder_double(Double x, Double y, 
//                 const TFheGateBootstrappingCloudKeySet *bk, const LweParams *in_out_params, TFheGateBootstrappingSecretKeySet* key) {
//     Double result;
// 	LweSample* a = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,bk->params);
// 	LweSample* b = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,bk->params);

//     // carries
//     LweSample *carry = new_LweSample_array(2, in_out_params);

//     int counter = integerbitsize - 1;
//     for (int i=0; i < integerbitsize; i++){
// 		bootsCOPY(&a[counter],&x.integerpart[i],bk);
// 		bootsCOPY(&b[counter],&y.integerpart[i],bk);
//         counter--;
// 	}

//     counter = integerbitsize + fractionbitsize - 1;
// 	for (int i=integerbitsize; i < (integerbitsize + fractionbitsize); i++){
// 		bootsCOPY(&a[counter],&x.fractionpart[i-integerbitsize],bk);
// 		bootsCOPY(&b[counter],&y.fractionpart[i-integerbitsize],bk);
//         counter--;

// 		// //
// 		// int decryptedbit = bootsSymDecrypt(&a[i],key);
// 		// cout << "decryptedbit[" << i << "] = " << decryptedbit << endl;
// 		// //

// 		// bootsCOPY(&c[i],&input1.fractionpart[i-integerbitsize],bk);
// 		// bootsCOPY(&d[i],&input2.fractionpart[i-integerbitsize],bk);

// 	}
// 	// double decryptedfraction = decryptFractionpart(&a[integerbitsize], key);
// 	// cout << "decryptedfraction = " << decryptedfraction << endl;
// 	// double decryptedfraction2 = decryptFractionpart(&b[integerbitsize], key);
// 	// cout << "decryptedfraction2 = " << decryptedfraction2 << endl;
	
    
    
//     // //
// 	// for (int i=0; i < fractionbitsize; i++){
// 	// 	bootsCOPY(&c[i],&input1.fractionpart[i],bk);
// 	// 	bootsCOPY(&d[i],&input2.fractionpart[i],bk);

// 	// }
// 	// //


// 	LweSample *sum = new_gate_bootstrapping_ciphertext_array(numberofbits + 1,bk->params);

//     full_adder_doublehelper(sum, a, b, numberofbits, bk, in_out_params, key);

//     result.integerpart = sum;
// 	result.fractionpart = sum + integerbitsize; 

//     //TODO: deallocate a and b?

//     return result;

// }

// //calculate x-y
// void full_subtractor(LweSample *difference, const LweSample *x, const LweSample *y, const int32_t nb_bits,
//                 const TFheGateBootstrappingSecretKeySet *keyset) {
//     const LweParams *in_out_params = keyset->params->in_out_params;
//     // carries
//     LweSample *borrow = new_LweSample_array(2, in_out_params);
    
    
//     bootsSymEncrypt(borrow, 0, keyset); // first carry initialized to 0
//     // bootsCONSTANT(borrow, 0, &keyset->cloud);

    
//     // temps
//     LweSample *temp = new_LweSample_array(6, in_out_params);

//     for (int32_t i = 0; i < nb_bits; ++i) {
//         //sumi = xi XOR yi XOR carry(i-1) 
//         bootsXOR(temp, x + i, y + i, &keyset->cloud); // temp = xi XOR yi
//         bootsXOR(difference + i, temp, borrow, &keyset->cloud);

//         // carry = (xi AND yi) XOR (carry(i-1) AND (xi XOR yi))
//         bootsNOT(temp + 1, x + i, &keyset->cloud); // temp1 = xi'
//         bootsAND(temp + 2, temp + 1, borrow, &keyset->cloud); // temp2 = xi' AND Bin
//         bootsAND(temp + 3, temp + 1, y + i, &keyset->cloud);  // temp3 = xi' AND yi
//         bootsAND(temp + 4, y + i, borrow, &keyset->cloud);    //temp4 = yi AND Bin
//         bootsOR(temp + 5, temp + 2, temp + 3, &keyset->cloud); //temp5 = (xi' AND Bin) OR (xi' AND yi)
//         bootsOR(borrow + 1, temp + 5, temp + 4, &keyset->cloud);
//         bootsCOPY(borrow, borrow + 1, &keyset->cloud);
//     }
//     // bootsCOPY(difference + nb_bits, carry, &keyset->cloud);

//     delete_LweSample_array(6, temp);
//     delete_LweSample_array(2, borrow);
// }

//calculate x-y
void full_subtractor(LweSample *difference, const LweSample *x, const LweSample *y, const int32_t nb_bits,
                const TFheGateBootstrappingCloudKeySet *bk, const LweParams *in_out_params) {
    // carries
    LweSample *borrow = new_LweSample_array(2, in_out_params);
    
    // first carry initialized to 0
    bootsCONSTANT(borrow, 0, bk);
    
    // temps
    LweSample *temp = new_LweSample_array(6, in_out_params);

    for (int32_t i = 0; i < nb_bits; ++i) {
        //sumi = xi XOR yi XOR carry(i-1) 
        bootsXOR(temp, x + i, y + i, bk); // temp = xi XOR yi
        bootsXOR(difference + i, temp, borrow, bk);

        // carry = (xi AND yi) XOR (carry(i-1) AND (xi XOR yi))
        bootsNOT(temp + 1, x + i, bk); // temp1 = xi'
        bootsAND(temp + 2, temp + 1, borrow, bk); // temp2 = xi' AND Bin
        bootsAND(temp + 3, temp + 1, y + i, bk);  // temp3 = xi' AND yi
        bootsAND(temp + 4, y + i, borrow, bk);    //temp4 = yi AND Bin
        bootsOR(temp + 5, temp + 2, temp + 3, bk); //temp5 = (xi' AND Bin) OR (xi' AND yi)
        bootsOR(borrow + 1, temp + 5, temp + 4, bk);
        bootsCOPY(borrow, borrow + 1, bk);
    }
    // bootsCOPY(difference + nb_bits, carry, bk);

    delete_LweSample_array(6, temp);
    delete_LweSample_array(2, borrow);
}


void full_subtractor_doublehelper(LweSample *difference, const LweSample *x, const LweSample *y, const int32_t nb_bits,
                const TFheGateBootstrappingCloudKeySet *bk, const LweParams *in_out_params) {
    // carries
    LweSample *borrow = new_LweSample_array(2, in_out_params);
    
    // first carry initialized to 0
    bootsCONSTANT(borrow, 0, bk);
    
    // temps
    LweSample *temp = new_LweSample_array(6, in_out_params);

    // for (int32_t i = (nb_bits-1); i >= 0; --i) {
    for (int32_t i = 0; i < nb_bits; ++i) {
        //sumi = xi XOR yi XOR carry(i-1) 
        bootsXOR(temp, x + i, y + i, bk); // temp = xi XOR yi
        bootsXOR(difference + i, temp, borrow, bk);

        // carry = (xi AND yi) XOR (carry(i-1) AND (xi XOR yi))
        bootsNOT(temp + 1, x + i, bk); // temp1 = xi'
        bootsAND(temp + 2, temp + 1, borrow, bk); // temp2 = xi' AND Bin
        bootsAND(temp + 3, temp + 1, y + i, bk);  // temp3 = xi' AND yi
        bootsAND(temp + 4, y + i, borrow, bk);    //temp4 = yi AND Bin
        bootsOR(temp + 5, temp + 2, temp + 3, bk); //temp5 = (xi' AND Bin) OR (xi' AND yi)
        bootsOR(borrow + 1, temp + 5, temp + 4, bk);
        bootsCOPY(borrow, borrow + 1, bk);
    }
    // bootsCOPY(difference + nb_bits, carry, bk);

    delete_LweSample_array(6, temp);
    delete_LweSample_array(2, borrow);
}

//TODO: delete key argument
Double full_subtractor_double(Double x, Double y, 
                const TFheGateBootstrappingCloudKeySet *bk, const LweParams *in_out_params, TFheGateBootstrappingSecretKeySet* key) {
    Double result;
	LweSample* a = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,bk->params);
	LweSample* b = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,bk->params);

    // carries
    LweSample *carry = new_LweSample_array(2, in_out_params);

    for (int i=0; i < fractionbitsize; i++){
		bootsCOPY(&a[i],&x.fractionpart[i],bk);
		bootsCOPY(&b[i],&y.fractionpart[i],bk);
	}
	for (int i=fractionbitsize; i < (integerbitsize + fractionbitsize); i++){
		bootsCOPY(&a[i],&x.integerpart[i-fractionbitsize],bk);
		bootsCOPY(&b[i],&y.integerpart[i-fractionbitsize],bk);

		// //
		// int decryptedbit = bootsSymDecrypt(&a[i],key);
		// cout << "decryptedbit[" << i << "] = " << decryptedbit << endl;
		// //

		// bootsCOPY(&c[i],&input1.fractionpart[i-integerbitsize],bk);
		// bootsCOPY(&d[i],&input2.fractionpart[i-integerbitsize],bk);

	}
	// double decryptedfraction = decryptFractionpart(&a[0], key);
	// cout << "decryptedfraction = " << decryptedfraction << endl;
	// double decryptedfraction2 = decryptFractionpart(&b[0], key);
	// cout << "decryptedfraction2 = " << decryptedfraction2 << endl;
	// //
	// for (int i=0; i < fractionbitsize; i++){
	// 	bootsCOPY(&c[i],&input1.fractionpart[i],bk);
	// 	bootsCOPY(&d[i],&input2.fractionpart[i],bk);

	// }
	// //


	LweSample *difference = new_gate_bootstrapping_ciphertext_array(numberofbits,bk->params);

    full_subtractor_doublehelper(difference, a, b, numberofbits, bk, in_out_params);

    result.fractionpart = difference;
	result.integerpart = difference + fractionbitsize; 

    //TODO: deallocate a and b?

    return result;

}

// ? returns 1 if y >= x, 0 if y < x ???,  works only for positive integers
void comparison_MUX(LweSample *comp, const LweSample *x, const LweSample *y, const int32_t nb_bits,
                    const TFheGateBootstrappingCloudKeySet *bk, const LweParams *in_out_params) {
    // clock_t begin = clock();
    // carries
    LweSample *carry = new_LweSample_array(2, in_out_params);
    bootsCONSTANT(carry, 1, bk); // first carry initialized to 1
    // temps
    LweSample *temp = new_LweSample(in_out_params);

    for (int32_t i = 0; i < nb_bits; ++i) {
        bootsXOR(temp, x + i, y + i, bk); // temp = xi XOR yi
        bootsMUX(carry + 1, temp, y + i, carry, bk);
        bootsCOPY(carry, carry + 1, bk);
    }
    bootsCOPY(comp, carry, bk);

    delete_LweSample(temp);
    delete_LweSample_array(2, carry);
    // clock_t end = clock();
    // double elapsed_secs = double(end - begin) / CLOCKS_PER_SEC;
    // cout << "elapsed_sec to compare = " << elapsed_secs << endl;
}

// ? returns 1 if y >= x, 0 if y < x ???,  works only for positive integers
void comparison_MUX_double(LweSample *comp, Double x, Double y, const int32_t nb_bits,
                    const TFheGateBootstrappingCloudKeySet *bk, const LweParams *in_out_params) {
    // clock_t begin = clock();
    
	LweSample* a = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,bk->params);
	LweSample* b = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,bk->params);

    for (int i=0; i < fractionbitsize; i++){
		bootsCOPY(&a[i],&x.fractionpart[i],bk);
		bootsCOPY(&b[i],&y.fractionpart[i],bk);
	}
	for (int i=fractionbitsize; i < (integerbitsize + fractionbitsize); i++){
		bootsCOPY(&a[i],&x.integerpart[i-fractionbitsize],bk);
		bootsCOPY(&b[i],&y.integerpart[i-fractionbitsize],bk);

		// //
		// int decryptedbit = bootsSymDecrypt(&a[i],key);
		// cout << "decryptedbit[" << i << "] = " << decryptedbit << endl;
		// //

		// bootsCOPY(&c[i],&input1.fractionpart[i-integerbitsize],bk);
		// bootsCOPY(&d[i],&input2.fractionpart[i-integerbitsize],bk);

	}

    comparison_MUX(comp, a, b, nb_bits, bk, in_out_params);


    // clock_t end = clock();
    // double elapsed_secs = double(end - begin) / CLOCKS_PER_SEC;
    // cout << "elapsed_sec to compare = " << elapsed_secs << endl;
}

// //calculate x*y,  uses same number of bits to represent multiplication result, might cause overflow
// void full_multiplicator(LweSample *product, const LweSample *x, const LweSample *y, const int32_t nb_bits,
//                 const TFheGateBootstrappingCloudKeySet *bk, const LweParams *in_out_params, TFheGateBootstrappingSecretKeySet* key) {
//     int ai;

//     for (int j=0; j<nb_bits; j++){
//             ai = bootsSymDecrypt(&x[j], key);
//             cout << "x[" << j << "]" << " = " << ai << endl;
//     }
//     for (int j=0; j<nb_bits; j++){
//             ai = bootsSymDecrypt(&y[j], key);
//             cout << "y[" << j << "]" << " = " << ai << endl;
//     }
//     // temps
//     // LweSample *temp = new_LweSample_array(nb_bits, in_out_params);
//     const TFheGateBootstrappingParameterSet* params = key->params;
//     LweSample *temp = new_gate_bootstrapping_ciphertext_array(nb_bits,params);



//     LweSample *partialsum = new_LweSample_array(nb_bits + 1, in_out_params);
//     for (int j=0; j<nb_bits; j++){
//             ai = bootsSymDecrypt(&partialsum[j], key);
//             cout << "initial partialsum[" << j << "]" << " = " << ai << endl;
//     }
//     // for (int i=0; i<numberofbits; i++) {
//     //             int ai = bootsSymDecrypt(&product[i], key);
//     //             int_answer |= (ai<<i);
//     //         }


//     for (int i=0; i< nb_bits; i++){
//         cout << "doing " << i << "th loop" << endl;
//         for (int j=0; j<nb_bits; j++){
//             bootsAND(temp+j, &x[j], &y[i], bk);
//             ai = bootsSymDecrypt(&temp[j], key);
//             cout << "ai = " << ai << endl;
//         }
//         // LweSample *temp2 = new_LweSample_array(nb_bits, in_out_params);
//         LweSample *temp2 = new_gate_bootstrapping_ciphertext_array(nb_bits,params);
//         for (int j=0; j<nb_bits; j++){
//             bootsCOPY(&temp2[j], &partialsum[j], bk);
//         }
//         // bootsCOPY(temp2, partialsum, bk);
//         for (int j=0; j<nb_bits; j++){
//             ai = bootsSymDecrypt(&temp2[j], key);
//             cout << "copied temp2[" << j << "]" << " = " << ai << endl;
//         }
//         for (int j=0; j<nb_bits; j++){
//             ai = bootsSymDecrypt(&temp[j], key);
//             cout << "temp before addition temp[" << j << "]" << " = " << ai << endl;
//         }
//         for (int j=0; j<nb_bits; j++){
//             ai = bootsSymDecrypt(&partialsum[j], key);
//             cout << "partialsum before addition partialsum[" << j << "]" << " = " << ai << endl;
//         }
//         full_adder(partialsum, temp, temp2, nb_bits, bk, in_out_params, key);
//         // for (int j=0; j<nb_bits; j++){
//         //     ai = bootsSymDecrypt(&partialsum[j], key);
//         //     cout << "partialsum[" << j << "]" << " = " << ai << endl;
//         // }
//         int32_t int_answer = 0;
//         for (int j=0; j<nb_bits; j++) {
//             int ai = bootsSymDecrypt(&partialsum[j], key);
//             int_answer |= (ai<<j);
//         }
        
//         cout << "partialsum int_answer = " << int_answer << endl;
//         delete_LweSample_array(nb_bits, temp2);
//     }

//     bootsCOPY(product, partialsum, bk);

//     delete_LweSample_array(nb_bits, temp);
//     delete_LweSample_array(nb_bits, partialsum);
    
// }



// //calculate x*y,  uses same number of bits to represent multiplication result, might cause overflow
// //old version that works, but doubles number of bits 
// void full_multiplicator(LweSample *product, LweSample *x, LweSample *y, const int32_t nb_bits,
//                 const TFheGateBootstrappingCloudKeySet *bk, const LweParams *in_out_params, TFheGateBootstrappingSecretKeySet* key) {
    
//     clock_t begin = clock();

//     const TFheGateBootstrappingParameterSet* params = key->params;
    
//     LweSample *partialsum = new_LweSample_array(nb_bits*2+1, in_out_params);
    
//     for (int i=0; i < (nb_bits*2+1); i++){
//         bootsCONSTANT(&partialsum[i], 0, bk); // initialized to 0
//     }


//     for (int j=0; j<nb_bits; j++){
//         int ai = bootsSymDecrypt(&x[j], key);
//         cout << "x  's   ai[" << j << "] = " << ai << endl;
//     }
//     for (int j=0; j<nb_bits; j++){
//         int bi = bootsSymDecrypt(&y[j], key);
//         cout << "y   's   bi[" << j << "] = " << bi << endl;
//     }
    
//     // for (int i=0; i<(nb_bits*2+1); i++) {
//     //     bootsSymEncrypt(&partialsum[i], (0>>i)&1, key);
//     // }

//     // int decryptedx = decryptLweSample(x, nb_bits, key);
//     // int decryptedy = decryptLweSample(y, nb_bits, key);
//     // cout << "x = " << decryptedx << endl;
//     // cout << "y = " << decryptedy << endl;

//     // temps
//     // LweSample *temp = new_LweSample_array(nb_bits, in_out_params);

//     //temp used to store ANDed value
//     LweSample *temp = new_gate_bootstrapping_ciphertext_array(nb_bits,params);

//     //temp2 used to store shifted ANDed value, filled with zeros in empty bits 
//     LweSample *temp2 = new_gate_bootstrapping_ciphertext_array(nb_bits * 2,params);

//     //temp3 used to store partialsum temporalily 
//     LweSample *temp3 = new_gate_bootstrapping_ciphertext_array(nb_bits * 2,params);

//     for (int i=0; i< nb_bits; i++){
//         cout << "doing " << i << "th bit" << endl;

//         //ybit being used to AND
//         LweSample* ybit = y+i;    
        
//         //ANDing
//         for (int j=0; j < nb_bits; j++){
//             bootsAND(temp+j, x+j, ybit, bk);
//         }

//         //shifting
//         for (int j=0; j < i; j++){
//             bootsCONSTANT(temp2+j, 0, bk);
//         }

//         for (int j=i; j < (i+nb_bits); j++){
//             bootsCOPY(temp2+j, temp + j - i, bk);
//         }

//         for (int j=i+nb_bits; j<(nb_bits*2); j++){
//             bootsCONSTANT(temp2+j, 0, bk);
//         }
//         //


//         //copy partialsum to temp3
//         for (int j=0; j < (nb_bits*2); j++){
//             bootsCOPY(temp3+j, partialsum+j, bk);
//         }

//         //
//         cout << "partialsum values " << endl;
//         for (int j=0; j<(nb_bits*2); j++){
//             int ai = bootsSymDecrypt(&partialsum[j], key);
//             cout << "ai[" << j << "] = " << ai << endl;
//         }
//         //
//         cout << "temp2 values " << endl;
//         for (int j=0; j<(nb_bits*2); j++){
//             int ai = bootsSymDecrypt(&temp2[j], key);
//             cout << "ai[" << j << "] = " << ai << endl;
//         }
//         //
//         cout << "temp3 values " << endl;
//         for (int j=0; j<(nb_bits*2); j++){
//             int ai = bootsSymDecrypt(&temp3[j], key);
//             cout << "ai[" << j << "] = " << ai << endl;
//         }
//         //
//         //
        

//         full_adder(partialsum, temp3, temp2, nb_bits*2, bk, in_out_params, key);
//     }

//     // full_adder(partialsum, x, y, nb_bits, bk, in_out_params, key);
    
//     // int decryptedsum = decryptLweSample(partialsum, nb_bits, key);
//     // cout << "decryptedsum = " << decryptedsum << endl;
    
//     for (int i=0; i < (nb_bits*2); i++){
//         bootsCOPY(product+i, partialsum+i, bk);
//     }
//     // product = partialsum;
    
//     //TODO: deallocate pointers
//     // delete_LweSample_array(nb_bits+1, partialsum);

//     clock_t end = clock();
//     double elapsed_secs = double(end - begin) / CLOCKS_PER_SEC;
//     cout << "elapsed secs = " << elapsed_secs << endl;

// }

//calculate x*y,  uses same number of bits to represent multiplication result, might cause overflow
//new version, doubles bits, and then truncates the first nb_bits in the product before returning
//version that does not use threads
void full_multiplicator(LweSample *product, LweSample *x, LweSample *y, const int32_t nb_bits,
                const TFheGateBootstrappingCloudKeySet *bk, const LweParams *in_out_params, TFheGateBootstrappingSecretKeySet* key) {
    
    // clock_t begin = clock();

    const TFheGateBootstrappingParameterSet* params = key->params;
    
    LweSample *partialsum = new_LweSample_array(nb_bits*2+1, in_out_params);
    
    for (int i=0; i < (nb_bits*2+1); i++){
        bootsCONSTANT(&partialsum[i], 0, bk); // initialized to 0
    }


    // for (int j=0; j<nb_bits; j++){
    //     int ai = bootsSymDecrypt(&x[j], key);
    //     cout << "x  's   ai[" << j << "] = " << ai << endl;
    // }
    // for (int j=0; j<nb_bits; j++){
    //     int bi = bootsSymDecrypt(&y[j], key);
    //     cout << "y   's   bi[" << j << "] = " << bi << endl;
    // }
    
    // for (int i=0; i<(nb_bits*2+1); i++) {
    //     bootsSymEncrypt(&partialsum[i], (0>>i)&1, key);
    // }

    // int decryptedx = decryptLweSample(x, nb_bits, key);
    // int decryptedy = decryptLweSample(y, nb_bits, key);
    // cout << "x = " << decryptedx << endl;
    // cout << "y = " << decryptedy << endl;



    // temps
    // LweSample *temp = new_LweSample_array(nb_bits, in_out_params);

    //temp used to store ANDed value
    LweSample *temp = new_gate_bootstrapping_ciphertext_array(nb_bits,params);

    //temp2 used to store shifted ANDed value, filled with zeros in empty bits 
    LweSample *temp2 = new_gate_bootstrapping_ciphertext_array(nb_bits * 2,params);

    //temp3 used to store partialsum temporalily 
    LweSample *temp3 = new_gate_bootstrapping_ciphertext_array(nb_bits * 2,params);

    for (int i=0; i< nb_bits; i++){
        // cout << "doing " << i << "th bit" << endl;

        //ybit being used to AND
        LweSample* ybit = y+i;    
        
        //ANDing
        for (int j=0; j < nb_bits; j++){
            bootsAND(temp+j, x+j, ybit, bk);
        }

        //shifting
        for (int j=0; j < i; j++){
            bootsCONSTANT(temp2+j, 0, bk);
        }

        for (int j=i; j < (i+nb_bits); j++){
            bootsCOPY(temp2+j, temp + j - i, bk);
        }

        for (int j=i+nb_bits; j<(nb_bits*2); j++){
            bootsCONSTANT(temp2+j, 0, bk);
        }
        //


        //copy partialsum to temp3
        for (int j=0; j < (nb_bits*2); j++){
            bootsCOPY(temp3+j, partialsum+j, bk);
        }

        // //
        // cout << "partialsum values " << endl;
        // for (int j=0; j<(nb_bits*2); j++){
        //     int ai = bootsSymDecrypt(&partialsum[j], key);
        //     cout << "ai[" << j << "] = " << ai << endl;
        // }
        // //
        // cout << "temp2 values " << endl;
        // for (int j=0; j<(nb_bits*2); j++){
        //     int ai = bootsSymDecrypt(&temp2[j], key);
        //     cout << "ai[" << j << "] = " << ai << endl;
        // }
        // //
        // cout << "temp3 values " << endl;
        // for (int j=0; j<(nb_bits*2); j++){
        //     int ai = bootsSymDecrypt(&temp3[j], key);
        //     cout << "ai[" << j << "] = " << ai << endl;
        // }
        // //
        // //
        

        full_adder(partialsum, temp3, temp2, nb_bits*2, bk, in_out_params, key);
    }

    // full_adder(partialsum, x, y, nb_bits, bk, in_out_params, key);
    
    // int decryptedsum = decryptLweSample(partialsum, nb_bits, key);
    // cout << "decryptedsum = " << decryptedsum << endl;
    
    // cout << "start of final partialsum decrypted" << endl;
    for (int i=0; i < (nb_bits*2); i++){
        // int ai = bootsSymDecrypt(&partialsum[i], key);
        // cout << "ai[" << i << "] = " << ai << endl;
        bootsCOPY(product+i, partialsum+i, bk);
    }
    // cout << "end of final partialsum decrypted" << endl;
    
    // product = partialsum;
    
    //TODO: deallocate pointers
    delete_LweSample_array(nb_bits+1, partialsum);

    // clock_t end = clock();
    // double elapsed_secs = double(end - begin) / CLOCKS_PER_SEC;
    // cout << "elapsed secs = " << elapsed_secs << endl;

}


//TODO: delete key argument
//threaded version of full_adder
void full_adder_thread(promise<LweSample*> && p, const LweSample *x, const LweSample *y, const int32_t nb_bits,
                const TFheGateBootstrappingCloudKeySet *bk, const LweParams *in_out_params, TFheGateBootstrappingSecretKeySet* key) {
    // int decryptedx = decryptLweSample(x, nb_bits, key);
    // int decryptedy = decryptLweSample(y, nb_bits, key);
    
    // cout << "decryptedx = " << decryptedx << endl;
    // cout << "decryptedy = " << decryptedy << endl;

    LweSample* sum = new_LweSample_array(nb_bits + 1, in_out_params);

    // carries
    LweSample *carry = new_LweSample_array(2, in_out_params);
    // first carry initialized to 0
    bootsCONSTANT(carry, 0, bk);
    // temps
    LweSample *temp = new_LweSample_array(3, in_out_params);

    for (int32_t i = 0; i < nb_bits; ++i) {

        // int ai = bootsSymDecrypt(&x[i], key);
        // cout << "decrypted x[" << i << "] = " << ai << endl;
        // ai = bootsSymDecrypt(&y[i], key);
        // cout << "decrypted y[" << i << "] = " << ai << endl;

        //sumi = xi XOR yi XOR carry(i-1) 
        bootsXOR(temp, x + i, y + i, bk); // temp = xi XOR yi
        bootsXOR(sum + i, temp, carry, bk);

        
        // int decryptedbit = bootsSymDecrypt(sum + i, key);
        // cout << "sum[" << i << "] = " << decryptedbit << endl;
        


        // carry = (xi AND yi) XOR (carry(i-1) AND (xi XOR yi))
        bootsAND(temp + 1, x + i, y + i, bk); // temp1 = xi AND yi
        bootsAND(temp + 2, carry, temp, bk); // temp2 = carry AND temp
        bootsXOR(carry + 1, temp + 1, temp + 2, bk);

        // int decryptedcarry = bootsSymDecrypt(carry + 1, key);
        // cout << "carry[" << i << "] = " << decryptedcarry << endl;

        bootsCOPY(carry, carry + 1, bk);
    }
    bootsCOPY(sum + nb_bits, carry, bk);

    p.set_value(sum);

    delete_LweSample_array(3, temp);
    delete_LweSample_array(2, carry);
}

// threaded helper that is to be used in full_multiplicator
void full_multiplicator_helper(void *threadarg){
    struct multiplicator_data *struct_data;
    struct_data = (struct multiplicator_data *) threadarg;
    LweSample *product = struct_data->product; 
    LweSample *x = struct_data->x; 
    LweSample *y = struct_data->y; 
    const int32_t nb_bits = struct_data->nb_bits;
    const TFheGateBootstrappingCloudKeySet *bk = struct_data->bk; 
    const LweParams *in_out_params = struct_data->in_out_params; 
    TFheGateBootstrappingSecretKeySet* key = struct_data->key;
    int i = struct_data->i;
    const TFheGateBootstrappingParameterSet* params = key->params;

    LweSample *thisthreadssum = new_LweSample_array(nb_bits*2+1, in_out_params);

    for (int i=0; i < (nb_bits*2+1); i++){
        bootsCONSTANT(&thisthreadssum[i], 0, bk); // initialized to 0
    }


    //temp used to store ANDed value
    LweSample *temp = new_gate_bootstrapping_ciphertext_array(nb_bits,params);

    //temp2 used to store shifted ANDed value, filled with zeros in empty bits 
    LweSample *temp2 = new_gate_bootstrapping_ciphertext_array(nb_bits * 2,params);

    //temp3 used to store another shifted ANDed value 
    LweSample *temp3 = new_gate_bootstrapping_ciphertext_array(nb_bits * 2,params);

    //ybit being used to AND
    LweSample* ybit = y+i;    
    
    //ANDing
    for (int j=0; j < nb_bits; j++){
        bootsAND(temp+j, x+j, ybit, bk);
    }

    //shifting
    for (int j=0; j < i; j++){
        bootsCONSTANT(temp2+j, 0, bk);
    }

    for (int j=i; j < (i+nb_bits); j++){
        bootsCOPY(temp2+j, temp + j - i, bk);
    }

    for (int j=i+nb_bits; j<(nb_bits*2); j++){
        bootsCONSTANT(temp2+j, 0, bk);
    }
    //


    // to calculate next ANDed value
    i++;
    //ybit being used to AND
    ybit = y+i;    
    
    //ANDing
    for (int j=0; j < nb_bits; j++){
        bootsAND(temp+j, x+j, ybit, bk);
    }

    //shifting
    for (int j=0; j < i; j++){
        bootsCONSTANT(temp3+j, 0, bk);
    }

    for (int j=i; j < (i+nb_bits); j++){
        bootsCOPY(temp3+j, temp + j - i, bk);
    }

    for (int j=i+nb_bits; j<(nb_bits*2); j++){
        bootsCONSTANT(temp3+j, 0, bk);
    }
    //



    // //copy partialsum to temp3
    // for (int j=0; j < (nb_bits*2); j++){
    //     bootsCOPY(temp3+j, thisthreadssum+j, bk);
    // }

    // //
    // cout << "partialsum values " << endl;
    // for (int j=0; j<(nb_bits*2); j++){
    //     int ai = bootsSymDecrypt(&partialsum[j], key);
    //     cout << "ai[" << j << "] = " << ai << endl;
    // }
    // //
    // cout << "temp2 values " << endl;
    // for (int j=0; j<(nb_bits*2); j++){
    //     int ai = bootsSymDecrypt(&temp2[j], key);
    //     cout << "ai[" << j << "] = " << ai << endl;
    // }
    // //
    // cout << "temp3 values " << endl;
    // for (int j=0; j<(nb_bits*2); j++){
    //     int ai = bootsSymDecrypt(&temp3[j], key);
    //     cout << "ai[" << j << "] = " << ai << endl;
    // }
    // //
    // //
    

    full_adder(thisthreadssum, temp3, temp2, nb_bits*2, bk, in_out_params, key);
}

// //calculate x*y,  uses same number of bits to represent multiplication result, might cause overflow
// //new version, doubles bits, and then truncates the first nb_bits in the product before returning
// //version that uses threads, version 2
// void full_multiplicator(LweSample *product, LweSample *x, LweSample *y, const int32_t nb_bits,
//                 const TFheGateBootstrappingCloudKeySet *bk, const LweParams *in_out_params, TFheGateBootstrappingSecretKeySet* key) {
    
//     // clock_t begin = clock();

//     const TFheGateBootstrappingParameterSet* params = key->params;

//     pthread_t threads[nb_bits/2];
//     struct multiplicator_data md[nb_bits/2];
//     int rc;
//     // pthread_attr_t attr;
//     void *status;

//     // // Initialize and set thread joinable
//     // pthread_attr_init(&attr);
//     // pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    
//     // LweSample *partialsum = new_LweSample_array(nb_bits*2+1, in_out_params);
    
//     // for (int i=0; i < (nb_bits*2+1); i++){
//     //     bootsCONSTANT(&partialsum[i], 0, bk); // initialized to 0
//     // }


//     // for (int j=0; j<nb_bits; j++){
//     //     int ai = bootsSymDecrypt(&x[j], key);
//     //     cout << "x  's   ai[" << j << "] = " << ai << endl;
//     // }
//     // for (int j=0; j<nb_bits; j++){
//     //     int bi = bootsSymDecrypt(&y[j], key);
//     //     cout << "y   's   bi[" << j << "] = " << bi << endl;
//     // }
    
//     // for (int i=0; i<(nb_bits*2+1); i++) {
//     //     bootsSymEncrypt(&partialsum[i], (0>>i)&1, key);
//     // }

//     // int decryptedx = decryptLweSample(x, nb_bits, key);
//     // int decryptedy = decryptLweSample(y, nb_bits, key);
//     // cout << "x = " << decryptedx << endl;
//     // cout << "y = " << decryptedy << endl;



//     // temps
//     // LweSample *temp = new_LweSample_array(nb_bits, in_out_params);

//     // //temp used to store ANDed value
//     // LweSample *temp = new_gate_bootstrapping_ciphertext_array(nb_bits,params);

//     // //temp2 used to store shifted ANDed value, filled with zeros in empty bits 
//     // LweSample *temp2 = new_gate_bootstrapping_ciphertext_array(nb_bits * 2,params);

//     // //temp3 used to store partialsum temporalily 
//     // LweSample *temp3 = new_gate_bootstrapping_ciphertext_array(nb_bits * 2,params);

//     for (int i=0; i< nb_bits; i++){
//         // cout << "doing " << i << "th bit" << endl;
//         if (i % 2 == 1){
//             continue;
//         }

//         cout << "main() : creating thread, " << i << endl;
//         md[i/2].product = product;
//         md[i/2].i = i;
//         md[i/2].in_out_params = in_out_params;
//         md[i/2].key = key;
//         md[i/2].bk = bk;
//         md[i/2].nb_bits = nb_bits;
//         md[i/2].x = x;
//         md[i/2].y = y;

//         rc = pthread_create(&threads[i/2], NULL, full_multiplicator_helper, (void *)&md[i/2]);
        
//         if (rc) {
//             cout << "Error:unable to create thread," << rc << endl;
//             exit(-1);
//         }

//         // //ybit being used to AND
//         // LweSample* ybit = y+i;    
        
//         // //ANDing
//         // for (int j=0; j < nb_bits; j++){
//         //     bootsAND(temp+j, x+j, ybit, bk);
//         // }

//         // //shifting
//         // for (int j=0; j < i; j++){
//         //     bootsCONSTANT(temp2+j, 0, bk);
//         // }

//         // for (int j=i; j < (i+nb_bits); j++){
//         //     bootsCOPY(temp2+j, temp + j - i, bk);
//         // }

//         // for (int j=i+nb_bits; j<(nb_bits*2); j++){
//         //     bootsCONSTANT(temp2+j, 0, bk);
//         // }
//         // //


//         // //copy partialsum to temp3
//         // for (int j=0; j < (nb_bits*2); j++){
//         //     bootsCOPY(temp3+j, partialsum+j, bk);
//         // }

//         // // //
//         // // cout << "partialsum values " << endl;
//         // // for (int j=0; j<(nb_bits*2); j++){
//         // //     int ai = bootsSymDecrypt(&partialsum[j], key);
//         // //     cout << "ai[" << j << "] = " << ai << endl;
//         // // }
//         // // //
//         // // cout << "temp2 values " << endl;
//         // // for (int j=0; j<(nb_bits*2); j++){
//         // //     int ai = bootsSymDecrypt(&temp2[j], key);
//         // //     cout << "ai[" << j << "] = " << ai << endl;
//         // // }
//         // // //
//         // // cout << "temp3 values " << endl;
//         // // for (int j=0; j<(nb_bits*2); j++){
//         // //     int ai = bootsSymDecrypt(&temp3[j], key);
//         // //     cout << "ai[" << j << "] = " << ai << endl;
//         // // }
//         // // //
//         // // //
        

//         // full_adder(partialsum, temp3, temp2, nb_bits*2, bk, in_out_params, key);
//     }

//     // free attribute and wait for the other threads
//     // pthread_attr_destroy(&attr);
//     for(int i = 0; i < (nb_bits/2); i++ ) {
//         rc = pthread_join(threads[i], &status);
//         if (rc) {
//             cout << "Error:unable to join," << rc << endl;
//             exit(-1);
//         }
        
//         cout << "Main: completed thread id :" << i ;
//         cout << "  exiting with status :" << status << endl;
//     }

//     cout << "Main: program exiting." << endl;
//     pthread_exit(NULL);

//     // full_adder(partialsum, x, y, nb_bits, bk, in_out_params, key);
    
//     // int decryptedsum = decryptLweSample(partialsum, nb_bits, key);
//     // cout << "decryptedsum = " << decryptedsum << endl;
    
//     // // cout << "start of final partialsum decrypted" << endl;
//     // for (int i=0; i < (nb_bits*2); i++){
//     //     // int ai = bootsSymDecrypt(&partialsum[i], key);
//     //     // cout << "ai[" << i << "] = " << ai << endl;
//     //     bootsCOPY(product+i, partialsum+i, bk);
//     // }
//     // // cout << "end of final partialsum decrypted" << endl;
    
//     // product = partialsum;
    
//     // //TODO: deallocate pointers
//     // delete_LweSample_array(nb_bits+1, partialsum);

//     // clock_t end = clock();
//     // double elapsed_secs = double(end - begin) / CLOCKS_PER_SEC;
//     // cout << "elapsed secs = " << elapsed_secs << endl;

// }

// //calculate x*y,  uses same number of bits to represent multiplication result, might cause overflow
// //new version, doubles bits, and then truncates the first nb_bits in the product before returning
// //version that uses threads, version 1
// //TODO: remove assumption that nb_bits is in a power of 2
// void full_multiplicator(LweSample *product, LweSample *x, LweSample *y, const int32_t nb_bits,
//                 const TFheGateBootstrappingCloudKeySet *bk, const LweParams *in_out_params, TFheGateBootstrappingSecretKeySet* key) {
    
//     clock_t begin = clock();

//     const TFheGateBootstrappingParameterSet* params = key->params;
    
//     LweSample *partialsum = new_LweSample_array(nb_bits*2+1, in_out_params);
    
//     for (int i=0; i < (nb_bits*2+1); i++){
//         bootsCONSTANT(&partialsum[i], 0, bk); // initialized to 0
//     }


//     // for (int j=0; j<nb_bits; j++){
//     //     int ai = bootsSymDecrypt(&x[j], key);
//     //     cout << "x  's   ai[" << j << "] = " << ai << endl;
//     // }
//     // for (int j=0; j<nb_bits; j++){
//     //     int bi = bootsSymDecrypt(&y[j], key);
//     //     cout << "y   's   bi[" << j << "] = " << bi << endl;
//     // }
    
//     // for (int i=0; i<(nb_bits*2+1); i++) {
//     //     bootsSymEncrypt(&partialsum[i], (0>>i)&1, key);
//     // }

//     // int decryptedx = decryptLweSample(x, nb_bits, key);
//     // int decryptedy = decryptLweSample(y, nb_bits, key);
//     // cout << "x = " << decryptedx << endl;
//     // cout << "y = " << decryptedy << endl;



//     // temps
//     // LweSample *temp = new_LweSample_array(nb_bits, in_out_params);

//     //temp used to store ANDed value
//     LweSample *temp = new_gate_bootstrapping_ciphertext_array(nb_bits,params);

//     //temp2 used to store shifted ANDed value, filled with zeros in empty bits 
//     LweSample *temp2 = new_gate_bootstrapping_ciphertext_array(nb_bits * 2,params);

//     //temp3 used to store partialsum temporalily 
//     LweSample *temp3 = new_gate_bootstrapping_ciphertext_array(nb_bits * 2,params);

//     thread threads[nb_bits/2];

//     for (int i=0; i< nb_bits; i++){
//         LweSample *thispartialsum = new_LweSample_array(nb_bits*2+1, in_out_params);
    
//         for (int i=0; i < (nb_bits*2+1); i++){
//             bootsCONSTANT(&thispartialsum[i], 0, bk); // initialized to 0
//         }
//         if (i % 2 == 1){
//             continue;
//         }
//         cout << "doing " << i << "th bit" << endl;

//         //ybit being used to AND
//         LweSample* ybit = y+i;    
        
//         promise<LweSample*> p1;
//         // promise<LweSample*> p2;
//         auto f1 = p1.get_future();
//         // auto f2 = p2.get_future();

//         thread t(&full_adder_thread, move(p1), partialsum1, partialsum2, nb_bits*2, bk, in_out_params, key);

//         // thread t1(&full_multiplicator_helper, move(p1), x, ybit, nb_bits, i, bk, in_out_params, key);
//         // thread t2(&full_multiplicator_helper, move(p2), x, ybit+1, nb_bits, i, bk, in_out_params, key);
//         // t1.join();
//         // t2.join();
//         // LweSample* partialsum1 = f1.get();
//         // LweSample* partialsum2 = f2.get();
//         // full_adder(thispartialsum, partialsum1, partialsum2, nb_bits*2, bk, in_out_params, key);

//         //copy partialsum to temp3
//         for (int j=0; j < (nb_bits*2); j++){
//             bootsCOPY(temp3+j, partialsum+j, bk);
//         }


//         // full_multiplicator_helper(x, ybit, nb_bits, i, bk, in_out_params, key);
//         // full_multiplicator_helper(x, ybit+1, nb_bits, i, bk, in_out_params, key);

//         // //ANDing
//         // for (int j=0; j < nb_bits; j++){
//         //     bootsAND(temp+j, x+j, ybit, bk);
//         // }

//         // //shifting
//         // for (int j=0; j < i; j++){
//         //     bootsCONSTANT(temp2+j, 0, bk);
//         // }

//         // for (int j=i; j < (i+nb_bits); j++){
//         //     bootsCOPY(temp2+j, temp + j - i, bk);
//         // }

//         // for (int j=i+nb_bits; j<(nb_bits*2); j++){
//         //     bootsCONSTANT(temp2+j, 0, bk);
//         // }
//         // //


//         // //copy partialsum to temp3
//         // for (int j=0; j < (nb_bits*2); j++){
//         //     bootsCOPY(temp3+j, partialsum+j, bk);
//         // }

//         // // //
//         // // cout << "partialsum values " << endl;
//         // // for (int j=0; j<(nb_bits*2); j++){
//         // //     int ai = bootsSymDecrypt(&partialsum[j], key);
//         // //     cout << "ai[" << j << "] = " << ai << endl;
//         // // }
//         // // //
//         // // cout << "temp2 values " << endl;
//         // // for (int j=0; j<(nb_bits*2); j++){
//         // //     int ai = bootsSymDecrypt(&temp2[j], key);
//         // //     cout << "ai[" << j << "] = " << ai << endl;
//         // // }
//         // // //
//         // // cout << "temp3 values " << endl;
//         // // for (int j=0; j<(nb_bits*2); j++){
//         // //     int ai = bootsSymDecrypt(&temp3[j], key);
//         // //     cout << "ai[" << j << "] = " << ai << endl;
//         // // }
//         // // //
//         // // //
        

//         full_adder(partialsum, temp3, thispartialsum, nb_bits*2, bk, in_out_params, key);
//     }

//     // full_adder(partialsum, x, y, nb_bits, bk, in_out_params, key);
    
//     // int decryptedsum = decryptLweSample(partialsum, nb_bits, key);
//     // cout << "decryptedsum = " << decryptedsum << endl;
    
//     cout << "start of final partialsum decrypted" << endl;
//     for (int i=0; i < (nb_bits*2); i++){
//         int ai = bootsSymDecrypt(&partialsum[i], key);
//         cout << "ai[" << i << "] = " << ai << endl;
//         bootsCOPY(product+i, partialsum+i, bk);
//     }
//     cout << "end of final partialsum decrypted" << endl;
    
//     // product = partialsum;
    
//     //TODO: deallocate pointers
//     // delete_LweSample_array(nb_bits+1, partialsum);

//     clock_t end = clock();
//     double elapsed_secs = double(end - begin) / CLOCKS_PER_SEC;
//     cout << "elapsed secs = " << elapsed_secs << endl;

// }

// //calculate x*y,  uses same number of bits to represent multiplication result, might cause overflow
// //new version, doubles bits, and then truncates the first nb_bits in the product before returning
// //version that does uses threaded full_adders
// void full_multiplicator(LweSample *product, LweSample *x, LweSample *y, const int32_t nb_bits,
//                 const TFheGateBootstrappingCloudKeySet *bk, const LweParams *in_out_params, TFheGateBootstrappingSecretKeySet* key) {
    
//     clock_t begin = clock();

//     const TFheGateBootstrappingParameterSet* params = key->params;
    
//     LweSample *partialsum = new_LweSample_array(nb_bits*2+1, in_out_params);
    
//     for (int i=0; i < (nb_bits*2+1); i++){
//         bootsCONSTANT(&partialsum[i], 0, bk); // initialized to 0
//     }


//     // for (int j=0; j<nb_bits; j++){
//     //     int ai = bootsSymDecrypt(&x[j], key);
//     //     cout << "x  's   ai[" << j << "] = " << ai << endl;
//     // }
//     // for (int j=0; j<nb_bits; j++){
//     //     int bi = bootsSymDecrypt(&y[j], key);
//     //     cout << "y   's   bi[" << j << "] = " << bi << endl;
//     // }
    
//     // for (int i=0; i<(nb_bits*2+1); i++) {
//     //     bootsSymEncrypt(&partialsum[i], (0>>i)&1, key);
//     // }

//     // int decryptedx = decryptLweSample(x, nb_bits, key);
//     // int decryptedy = decryptLweSample(y, nb_bits, key);
//     // cout << "x = " << decryptedx << endl;
//     // cout << "y = " << decryptedy << endl;



//     // temps
//     // LweSample *temp = new_LweSample_array(nb_bits, in_out_params);

//     //temp used to store ANDed value
//     LweSample *temp = new_gate_bootstrapping_ciphertext_array(nb_bits,params);

//     //temp2 used to store shifted ANDed value, filled with zeros in empty bits 
//     LweSample *temp2 = new_gate_bootstrapping_ciphertext_array(nb_bits * 2,params);

//     //temp3 used to store partialsum temporalily 
//     LweSample *temp3 = new_gate_bootstrapping_ciphertext_array(nb_bits * 2,params);

//     //temp4 used to store another shifted ANDed value, filled with zeros in empty bits 
//     LweSample *temp4 = new_gate_bootstrapping_ciphertext_array(nb_bits * 2,params);

//     int counter = 0;

//     thread threads[nb_bits/2];
//     // future<LweSample*> futures[nb_bits/2];
//     // list<future<LweSample*>> futures;
//     // list<future<LweSample*>>::iterator it;
//     vector<future<LweSample*>> futures;
//     // promise<LweSample*> promises[nb_bits/2];
//     for (int i=0; i< nb_bits; i++){
//         if(i % 2 == 1){
//             continue;
//         }
//         cout << "doing " << i << "th bit" << endl;

//         //ybit being used to AND
//         LweSample* ybit = y+i;    
        
//         //ANDing
//         for (int j=0; j < nb_bits; j++){
//             bootsAND(temp+j, x+j, ybit, bk);
//         }

//         //shifting
//         for (int j=0; j < i; j++){
//             bootsCONSTANT(temp2+j, 0, bk);
//         }

//         for (int j=i; j < (i+nb_bits); j++){
//             bootsCOPY(temp2+j, temp + j - i, bk);
//         }

//         for (int j=i+nb_bits; j<(nb_bits*2); j++){
//             bootsCONSTANT(temp2+j, 0, bk);
//         }
//         //

//         //ybit being used to AND
//         ybit = y+i+1;    
        
//         //ANDing
//         for (int j=0; j < nb_bits; j++){
//             bootsAND(temp+j, x+j, ybit, bk);
//         }

//         //shifting
//         for (int j=0; j < i+1; j++){
//             bootsCONSTANT(temp4+j, 0, bk);
//         }

//         for (int j=i+1; j < (i+1+nb_bits); j++){
//             bootsCOPY(temp4+j, temp + j - i-1, bk);
//         }

//         for (int j=i+1+nb_bits; j<(nb_bits*2); j++){
//             bootsCONSTANT(temp4+j, 0, bk);
//         }
//         //

        
//         std::promise<LweSample*> p;
//         auto f = p.get_future();

//         threads[counter] = thread(&full_adder_thread, move(p), temp2, temp4, nb_bits*2, bk, in_out_params, key);


//         // LweSample* temppartialsum = f.get();
//         // cout << "start of temppartialsum" << endl;
//         // for (int j=0; j<(nb_bits*2); j++){
//         //     int ai = bootsSymDecrypt(&temppartialsum[j], key);
//         //     cout << "ai[" << j << "] = " << ai << endl;
//         // }
//         // cout << "end of temppartialsum" << endl;


//         // futures[counter] = f;
//         // it = futures.begin();
//         // futures.insert(it,move(f));
//         futures.push_back(move(f));
//         // promises[counter] = p;
//         counter++; 

//     }

//     for (int i=0; i < (nb_bits/2); i++){
//         threads[i].join();
//     }

//     // counter = 0;
//     //concurrently sum the nb_bits/2 partialsum values
//     for (int i=0; i < (nb_bits/2); i++){
//         // if (i % 2 == 1){
//         //     continue;
//         // }
//         // list<future<LweSample*>>::iterator iter = futures.end();
//         // --iter;
//         // future<LweSample*> thisfuture = *iter;
//         // LweSample* partialsum1 = thisfuture.get();
//         LweSample* partialsum1 = futures.back().get();
//         LweSample* partialsum2 = futures.front().get();
//         cout << "start of partialsum1" << endl;
//         for (int j=0; j<(nb_bits*2); j++){
//             int ai = bootsSymDecrypt(&partialsum1[j], key);
//             cout << "ai[" << j << "] = " << ai << endl;
//         }
//         cout << "end of partialsum1" << endl;

//         cout << "start of partialsum2" << endl;
//         for (int j=0; j<(nb_bits*2); j++){
//             int ai = bootsSymDecrypt(&partialsum2[j], key);
//             cout << "ai[" << j << "] = " << ai << endl;
//         }
//         cout << "end of partialsum2" << endl;

//         futures.pop_back();
//         // counter++;
//         // LweSample* partialsum2 = futures[counter].get();

//         //copy partialsum to temp3
//         for (int j=0; j < (nb_bits*2); j++){
//             bootsCOPY(temp3+j, partialsum+j, bk);
//         }

//         full_adder(partialsum, partialsum1, temp3, nb_bits*2, bk, in_out_params, key);
        
//     }    


    
//     cout << "start of final partialsum decrypted" << endl;
//     for (int i=0; i < (nb_bits*2); i++){
//         int ai = bootsSymDecrypt(&partialsum[i], key);
//         cout << "ai[" << i << "] = " << ai << endl;
//         bootsCOPY(product+i, partialsum+i, bk);
//     }
//     cout << "end of final partialsum decrypted" << endl;
    
//     // product = partialsum;
    
//     //TODO: deallocate pointers
//     // delete_LweSample_array(nb_bits+1, partialsum);

//     clock_t end = clock();
//     double elapsed_secs = double(end - begin) / CLOCKS_PER_SEC;
//     cout << "elapsed secs = " << elapsed_secs << endl;

// }

// //thread helper for full_multiplicator
// void full_multiplicator_helper(promise<LweSample*> && p, LweSample *x, LweSample* ybit, const int32_t nb_bits, int i, const TFheGateBootstrappingCloudKeySet *bk, const LweParams *in_out_params, TFheGateBootstrappingSecretKeySet* key){
//     const TFheGateBootstrappingParameterSet* params = key->params;
    
//     //TODO: deallocate these
//     LweSample *partialsum = new_LweSample_array(nb_bits*2+1, in_out_params);
//     for (int i=0; i < (nb_bits*2+1); i++){
//         bootsCONSTANT(&partialsum[i], 0, bk); // initialized to 0
//     }
//     //temp used to store ANDed value
//     LweSample *temp = new_gate_bootstrapping_ciphertext_array(nb_bits,params);

//     //temp2 used to store shifted ANDed value, filled with zeros in empty bits 
//     LweSample *temp2 = new_gate_bootstrapping_ciphertext_array(nb_bits * 2,params);

//     //temp3 used to store partialsum temporalily 
//     LweSample *temp3 = new_gate_bootstrapping_ciphertext_array(nb_bits * 2,params);

//     //ANDing
//     for (int j=0; j < nb_bits; j++){
//         bootsAND(temp+j, x+j, ybit, bk);
//     }

//     //shifting
//     for (int j=0; j < i; j++){
//         bootsCONSTANT(temp2+j, 0, bk);
//     }

//     for (int j=i; j < (i+nb_bits); j++){
//         bootsCOPY(temp2+j, temp + j - i, bk);
//     }

//     for (int j=i+nb_bits; j<(nb_bits*2); j++){
//         bootsCONSTANT(temp2+j, 0, bk);
//     }
//     //


//     //copy partialsum to temp3
//     for (int j=0; j < (nb_bits*2); j++){
//         bootsCOPY(temp3+j, partialsum+j, bk);
//     }

//     // //
//     // cout << "partialsum values " << endl;
//     // for (int j=0; j<(nb_bits*2); j++){
//     //     int ai = bootsSymDecrypt(&partialsum[j], key);
//     //     cout << "ai[" << j << "] = " << ai << endl;
//     // }
//     // //
//     // cout << "temp2 values " << endl;
//     // for (int j=0; j<(nb_bits*2); j++){
//     //     int ai = bootsSymDecrypt(&temp2[j], key);
//     //     cout << "ai[" << j << "] = " << ai << endl;
//     // }
//     // //
//     // cout << "temp3 values " << endl;
//     // for (int j=0; j<(nb_bits*2); j++){
//     //     int ai = bootsSymDecrypt(&temp3[j], key);
//     //     cout << "ai[" << j << "] = " << ai << endl;
//     // }
//     // //
//     // //
    

//     // full_adder(partialsum, temp3, temp2, nb_bits*2, bk, in_out_params, key);

//     p.set_value(temp2);
// }




// //calculate x*y,  uses same number of bits to represent multiplication result, might cause overflow
// void full_multiplicator_doublehelper(LweSample *product, LweSample *x, LweSample *y, const int32_t nb_bits,
//                 const TFheGateBootstrappingCloudKeySet *bk, const LweParams *in_out_params, TFheGateBootstrappingSecretKeySet* key) {
    
//     clock_t begin = clock();

//     const TFheGateBootstrappingParameterSet* params = key->params;
    
//     LweSample *partialsum = new_LweSample_array(nb_bits*2+1, in_out_params);
    
//     for (int i=0; i < (nb_bits*2+1); i++){
//         bootsCONSTANT(&partialsum[i], 0, bk); // initialized to 0
//     }


//     for (int j=0; j<nb_bits; j++){
//         int ai = bootsSymDecrypt(&x[j], key);
//         cout << "x  's   ai[" << j << "] = " << ai << endl;
//     }
//     for (int j=0; j<nb_bits; j++){
//         int bi = bootsSymDecrypt(&y[j], key);
//         cout << "y   's   bi[" << j << "] = " << bi << endl;
//     }
    
//     // for (int i=0; i<(nb_bits*2+1); i++) {
//     //     bootsSymEncrypt(&partialsum[i], (0>>i)&1, key);
//     // }

//     // int decryptedx = decryptLweSample(x, nb_bits, key);
//     // int decryptedy = decryptLweSample(y, nb_bits, key);
//     // cout << "x = " << decryptedx << endl;
//     // cout << "y = " << decryptedy << endl;

//     // temps
//     // LweSample *temp = new_LweSample_array(nb_bits, in_out_params);

//     //temp used to store ANDed value
//     LweSample *temp = new_gate_bootstrapping_ciphertext_array(nb_bits,params);

//     //temp2 used to store shifted ANDed value, filled with zeros in empty bits 
//     LweSample *temp2 = new_gate_bootstrapping_ciphertext_array(nb_bits * 2,params);

//     //temp3 used to store partialsum temporalily 
//     LweSample *temp3 = new_gate_bootstrapping_ciphertext_array(nb_bits * 2,params);

//     for (int i=0; i< nb_bits; i++){
//         cout << "doing " << i << "th bit" << endl;

//         //ybit being used to AND
//         LweSample* ybit = y+i;    
        
//         //ANDing
//         for (int j=0; j < nb_bits; j++){
//             bootsAND(temp+j, x+j, ybit, bk);
//         }

//         //shifting
//         for (int j=0; j < i; j++){
//             bootsCONSTANT(temp2+j, 0, bk);
//         }

//         for (int j=i; j < (i+nb_bits); j++){
//             bootsCOPY(temp2+j, temp + j - i, bk);
//         }

//         for (int j=i+nb_bits; j<(nb_bits*2); j++){
//             bootsCONSTANT(temp2+j, 0, bk);
//         }
//         //


//         //copy partialsum to temp3
//         for (int j=0; j < (nb_bits*2); j++){
//             bootsCOPY(temp3+j, partialsum+j, bk);
//         }

//         //
//         cout << "partialsum values " << endl;
//         for (int j=0; j<(nb_bits*2); j++){
//             int ai = bootsSymDecrypt(&partialsum[j], key);
//             cout << "ai[" << j << "] = " << ai << endl;
//         }
//         //
//         cout << "temp2 values " << endl;
//         for (int j=0; j<(nb_bits*2); j++){
//             int ai = bootsSymDecrypt(&temp2[j], key);
//             cout << "ai[" << j << "] = " << ai << endl;
//         }
//         //
//         cout << "temp3 values " << endl;
//         for (int j=0; j<(nb_bits*2); j++){
//             int ai = bootsSymDecrypt(&temp3[j], key);
//             cout << "ai[" << j << "] = " << ai << endl;
//         }
//         //
//         //
        

//         full_adder(partialsum, temp3, temp2, nb_bits*2, bk, in_out_params, key);
//     }

//     // full_adder(partialsum, x, y, nb_bits, bk, in_out_params, key);
    
//     // int decryptedsum = decryptLweSample(partialsum, nb_bits, key);
//     // cout << "decryptedsum = " << decryptedsum << endl;
    
//     for (int i=0; i < (nb_bits*2); i++){
//         bootsCOPY(product+i, partialsum+i, bk);
//     }
//     // product = partialsum;
    
//     //TODO: deallocate pointers
//     // delete_LweSample_array(nb_bits+1, partialsum);

//     clock_t end = clock();
//     double elapsed_secs = double(end - begin) / CLOCKS_PER_SEC;
//     cout << "elapsed secs = " << elapsed_secs << endl;

// }

//calculate x*y,  uses same number of bits to represent multiplication result, might cause overflow
Double full_multiplicator_double(Double x, Double y, const int32_t nb_bits,
                const TFheGateBootstrappingCloudKeySet *bk, const LweParams *in_out_params, TFheGateBootstrappingSecretKeySet* key) {
    Double result;
    LweSample* a = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,bk->params);
	LweSample* b = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,bk->params);

    for (int i=0; i < fractionbitsize; i++){
		bootsCOPY(&a[i],&x.fractionpart[i],bk);
		bootsCOPY(&b[i],&y.fractionpart[i],bk);
	}
	for (int i=fractionbitsize; i < (integerbitsize + fractionbitsize); i++){
		bootsCOPY(&a[i],&x.integerpart[i-fractionbitsize],bk);
		bootsCOPY(&b[i],&y.integerpart[i-fractionbitsize],bk);

		// //
		// int decryptedbit = bootsSymDecrypt(&a[i],key);
		// cout << "decryptedbit[" << i << "] = " << decryptedbit << endl;
		// //

		// bootsCOPY(&c[i],&input1.fractionpart[i-integerbitsize],bk);
		// bootsCOPY(&d[i],&input2.fractionpart[i-integerbitsize],bk);

	}

    LweSample* product = new_LweSample_array(nb_bits*2, in_out_params);
    // full_multiplicator_doublehelper(product, a, b, nb_bits , bk, in_out_params, key);
    full_multiplicator(product, a, b, nb_bits , bk, in_out_params, key);

    // cout << "start of decrypted product " << endl;
    // for (int i=0; i < (nb_bits*2); i++){
    //     int ai = bootsSymDecrypt(&product[i], key);
    //     cout << "ai[" << i << "] = " << ai << endl;
    // }
    // cout << "end of decrypted product " << endl;

    // first (least significant) fractionbitsize bits of fractionpart are lost, last (most significant) integerbitsize of integerpart are lost
    result.fractionpart = product + fractionbitsize;
	result.integerpart = product + fractionbitsize * 2; 

    return result;
}


//calculate the square of Double of Eulcidean distances between the two given Double vectors
Double euclidean(Double vector1[], Double vector2[], const int numfeatures, const int32_t nb_bits,
                const TFheGateBootstrappingCloudKeySet *bk, const LweParams *in_out_params, TFheGateBootstrappingSecretKeySet* key){

    // clock_t begin = clock();
    
    const TFheGateBootstrappingParameterSet* params = bk->params;
    Double result;
    result.integerpart = new_gate_bootstrapping_ciphertext_array(integerbitsize,params);
    result.fractionpart = new_gate_bootstrapping_ciphertext_array(fractionbitsize,params);

    //intialize result to zeros
    for (int i=0; i < integerbitsize; i++){
        bootsCONSTANT(&result.integerpart[i], 0, bk); // initialized to 0
    }
    for (int i=0; i < fractionbitsize; i++){
        bootsCONSTANT(&result.fractionpart[i], 0, bk); // initialized to 0
    }

    for (int i=0; i < numfeatures; i++){
        Double thisdouble1 = vector1[i];
        Double thisdouble2 = vector2[i];


        LweSample *comp = new_LweSample(in_out_params);
        // ? returns 1 if thisdouble2 >= thisdouble1, 0 if thisdouble2 < thisdouble1 ???,  works only for positive integers
        comparison_MUX_double(comp, thisdouble1, thisdouble2, nb_bits, bk, in_out_params);
        Double difference1 = full_subtractor_double(thisdouble1, thisdouble2, bk, in_out_params, key);
        Double difference2 = full_subtractor_double(thisdouble2, thisdouble1, bk, in_out_params, key);

        Double absdifference;
        absdifference.integerpart = new_gate_bootstrapping_ciphertext_array(integerbitsize,params);
        absdifference.fractionpart = new_gate_bootstrapping_ciphertext_array(fractionbitsize,params);

        for (int j=0; j < integerbitsize; j++){
            // cout << "doing " << j << "th MUX" << endl;
            bootsMUX(absdifference.integerpart+j, comp, difference2.integerpart+j, difference1.integerpart+j, bk);
        }
        for (int j=0; j < fractionbitsize; j++){
            bootsMUX(absdifference.fractionpart+j, comp, difference2.fractionpart+j, difference1.fractionpart+j, bk);
        }

        // cout << "starting multiplication" << endl;
        Double product = full_multiplicator_double(absdifference, absdifference, nb_bits, bk, in_out_params, key);

        //temp used to hold current result 
        Double temp;
        temp.integerpart = new_gate_bootstrapping_ciphertext_array(integerbitsize,params);
        temp.fractionpart = new_gate_bootstrapping_ciphertext_array(fractionbitsize,params);
        for (int j=0; j < integerbitsize; j++){
            bootsCOPY(&temp.integerpart[j],&result.integerpart[j],bk);
        }
        for (int j=0; j < fractionbitsize; j++){
            bootsCOPY(&temp.fractionpart[j],&result.fractionpart[j],bk);
        }

        result = full_adder_double(temp, product, bk, in_out_params, key);


    }
    // clock_t end = clock();
    // double elapsed_secs = double(end - begin) / CLOCKS_PER_SEC;
    // cout << "time taken to do calculate Euclidean distance = " << elapsed_secs << endl;
    return result;
}

// void *thread_xor(void *arg)
// {
// 	struct CalcSet* input = (struct CalcSet*)arg;
//         bootsXOR(input->r,input->a,input->b,input->EK);

//         pthread_exit((void *)input->r);
// }
// void *thread_mux(void *arg)
// {
// 	struct CalcSet* input = (struct CalcSet*)arg;
// 	bootsMUX(input->r,input->a,input->b,input->c,input->EK);
	
//         pthread_exit((void *)input->r);
// }
// LweSample* CipherAdd(LweSample* a,LweSample* b,const TFheGateBootstrappingCloudKeySet* EK,int minbit) // special Add functions used for Multiplications
// {

//         LweSample *carry = new_gate_bootstrapping_ciphertext(EK->params);
//         LweSample *Result = new_gate_bootstrapping_ciphertext_array(numberofbits,EK->params);

// 	pthread_t thread[2];
//         struct CalcSet *in[2];


// 	for(int i= numberofbits-1; i>minbit ; i--)
// 	{
// 		bootsCOPY(&Result[i],&a[i],EK);
// 	}

//         for(int i= minbit ; i >= 0 ; i--)
//         {
//                 if(i == minbit)
//                 {
//                         bootsAND(carry,&a[i],&b[i],EK);
//                         bootsXOR(&Result[i],&a[i],&b[i],EK);
//                 }
//                 else
//                 {

// 			for(int num =0 ; num<2; num++)  in[num]= (struct CalcSet*)malloc(sizeof(struct CalcSet));

//                         LweSample *b1;
//                         b1 = new_gate_bootstrapping_ciphertext(EK->params);
//                         bootsXOR(b1,&a[i],&b[i],EK);

// 			LweSample *b2 = new_gate_bootstrapping_ciphertext(EK->params);
//                         bootsCOPY(b2,carry,EK);

//                         in[0]->r = &Result[i];
//                         in[0]->a = b1;
//                         in[0]->b = b2;
//                         in[0]->EK= EK;

//                         in[1]->r = carry;
//                         in[1]->a = b1;
//                         in[1]->b = b2;
//                         in[1]->c = &a[i];
//                         in[1]->EK= EK;

//                         pthread_create(&thread[0],NULL,&thread_xor,(void*)in[0]);
//                         pthread_create(&thread[1],NULL,&thread_mux,(void*)in[1]);

//                         pthread_join(thread[0],(void **)&b1);
//                         pthread_join(thread[1],(void **)&b2);


//                         //bootsXOR(&Result[i],b1,carry,EK);
//                         //bootsMUX(carry,b1,carry,&a[i],EK);
//                 }
//         }
//         return Result;
// }

// void *thread_adder(void *arg)
// {
//         struct CipherSet* input = (struct CipherSet*)arg;


//         LweSample* Ret = CipherAdd(input->a,input->b,input->EK,input->minbit);

// 	pthread_exit((void *)Ret);
// }

// void *thread_initializer(void *arg)
// {
// 	struct MulInitSet* input = (struct MulInitSet*)arg;
	
// 	input->C = new_gate_bootstrapping_ciphertext_array(numberofbits,input->EK->params);
// 	for(int i=input->ind;i<numberofbits;i++)	bootsAND(&input->C[i-input->ind],&input->a[numberofbits-1-input->ind],&input->b[i],input->EK);	
// 	for(int i=numberofbits-input->ind;i<numberofbits;i++)	bootsCONSTANT(&input->C[i],0,input->EK);
// 	pthread_exit((void *)input->C);
// }
// void *zero_initializer(void *arg)
// {
//         struct MulInitSet* input = (struct MulInitSet*)arg;

//         input->C = new_gate_bootstrapping_ciphertext_array(numberofbits,input->EK->params);
//         for(int i=0;i<numberofbits;i++)     bootsCONSTANT(&input->C[i],0,input->EK);
//         pthread_exit((void *)input->C);
// }

// LweSample* CipherMul(LweSample* a,LweSample* b,const TFheGateBootstrappingCloudKeySet* EK)	// O(2*n) algorithm = about 
// {
// 	int bin = 1;
// 	while(bin<numberofbits)	bin*=2;
// 	LweSample *Container[bin*2];
//         pthread_t init[bin];

//         /** Boost speed by initializing variables concurrently using threads **/

//         for(int i = 0 ; i < numberofbits ; i++)
//         {
//                 struct MulInitSet *in;
//                 in = (struct MulInitSet*)malloc(sizeof(struct MulInitSet));
//                 in->C = Container[i];
//                 in->a = a;
//                 in->b = b;
//                 in->EK = EK;
//                 in->ind = i;
//                 pthread_create(&init[i],NULL,&thread_initializer,(void*)in);
//         }
// 	for(int i = numberofbits ; i < bin ; i++)
// 	{
// 		struct MulInitSet *in;
//                 in = (struct MulInitSet*)malloc(sizeof(struct MulInitSet));
//                 in->C = Container[i];
//                 in->EK = EK;
//                 pthread_create(&init[i],NULL,&zero_initializer,(void*)in);
// 	}

//         /** Boost speed by using complete binary-tree based thread calculation **/


//         for(int i=0;i<bin;i++)      pthread_join(init[i],(void **)&Container[i]);

//         pthread_t thread[bin];

//         int len = bin/2;
//         int pivot = 0;
//         while(len>0)
//         {
//                 for(int i=0;i<len;i++)
//                 {
//                         struct CipherSet *in;
//                         in = (struct CipherSet*)malloc(sizeof(struct CipherSet));
//                         in->a = Container[pivot+i];
//                         in->b = Container[pivot+2*len-1-i];
// 			if(numberofbits>(i+1+pivot/2))	in->minbit = i+1+pivot/2;
// 			else	in->minbit = numberofbits-1;
//                         in->EK = EK;
//                         pthread_create(&thread[pivot/2+i],NULL,&thread_adder,(void *)in);
//                 }
//                 for(int i=0;i<len;i++)  pthread_join(thread[pivot/2+i],(void **)&Container[pivot+len*2+i]);
//                 pivot+=len*2;
//                 len/=2;
//         }
//         return Container[2*bin-2];
// }





//EXPORT void tLweExtractKey(LweKey* result, const TLweKey* key); //TODO: change the name and put in a .h
//EXPORT void tfhe_createLweBootstrappingKeyFFT(LweBootstrappingKeyFFT* bk, const LweKey* key_in, const TGswKey* rgsw_key);
//EXPORT void tfhe_bootstrapFFT(LweSample* result, const LweBootstrappingKeyFFT* bk, Torus32 mu1, Torus32 mu0, const LweSample* x);


int main(int argc, char *argv[]){
    if(argc!=7){
		printf("Usage : ./filename <num1> <num2> <mode> <bitsize> <integerbitsize> <fractionbitsize>\n");
        printf("Calculation mode :\n1) Addition\n2) Multiplication\n3) Subtraction\n4) Comparison\n 5) Addition using MUX\n 6) Double Addition\n 7) Double Subtraction\n 8) Test encryption of Double\n 9) Comparison between doubles\n 10)Multiplication between doubles\n 11)Eulcidean distance between encrypted double vectors>\n");
		exit(0);
	}

    //reads the secret key from file
    FILE* secret_key = fopen("secret.key","rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);

	//reads the cloud key from file
    FILE* cloud_key = fopen("cloud.key","rb");
    const TFheGateBootstrappingCloudKeySet* bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    fclose(cloud_key);

	//if necessary, the params are inside the key
    const TFheGateBootstrappingParameterSet* params = key->params;
    const LweParams *in_out_params = params->in_out_params;
    int32_t arg1,arg2,arg3;
	arg1 = atoi(argv[1]);
	arg2 = atoi(argv[2]);
    arg3 = atoi(argv[3]);
    numberofbits = atoi(argv[4]);
    integerbitsize = atoi(argv[5]);
    fractionbitsize = atoi(argv[6]);
    LweSample *ciphertext1 = new_gate_bootstrapping_ciphertext_array(numberofbits,params);
	LweSample *ciphertext2 = new_gate_bootstrapping_ciphertext_array(numberofbits,params);
    for (int i=0; i<numberofbits; i++) {
        bootsSymEncrypt(&ciphertext1[i], (arg1>>i)&1, key);
        bootsSymEncrypt(&ciphertext2[i], (arg2>>i)&1, key);
    }
    switch(arg3){
        case 1:{
            LweSample* sum = new_LweSample_array(numberofbits + 1, in_out_params);
            full_adder(sum, ciphertext1, ciphertext2, numberofbits, bk, in_out_params, key);
            //decrypt and rebuild the 32-bit plaintext answer
            int32_t int_answer = 0;
            for (int i=0; i<numberofbits; i++) {
                int ai = bootsSymDecrypt(&sum[i], key);
                int_answer |= (ai<<i);
            }
            
            cout << "addition int_answer = " << int_answer << endl;
            break;
        }
        case 2:{
            // LweSample* product = new_LweSample_array(numberofbits*2, in_out_params);
            // full_multiplicator(product, ciphertext1, ciphertext2, numberofbits,bk, in_out_params, key);
            // //decrypt and rebuild the 32-bit plaintext answer
            // int32_t int_answer = 0;
            // for (int i=0; i< (numberofbits*2); i++) {
            //     int ai = bootsSymDecrypt(&product[i], key);
            //     int_answer |= (ai<<i);
            // }
            
            // cout << "multiplication int_answer = " << int_answer << endl;


            LweSample* product = new_LweSample_array(numberofbits, in_out_params);
            full_multiplicator(product, ciphertext1, ciphertext2, numberofbits,bk, in_out_params, key);
            //decrypt and rebuild the 32-bit plaintext answer
            int32_t int_answer = 0;
            for (int i=0; i< (numberofbits); i++) {
                int ai = bootsSymDecrypt(&product[i], key);
                int_answer |= (ai<<i);
            }
            
            cout << "multiplication int_answer = " << int_answer << endl;


            // //
            // LweSample* product = CipherMul(ciphertext1,ciphertext2,&key->cloud);
            // int32_t int_answer = 0;
            // for (int i=0; i<numberofbits; i++) {
            //     int ai = bootsSymDecrypt(&product[i], key);
            //     int_answer |= (ai<<i);
            // }
            
            // cout << "multiplication int_answer = " << int_answer << endl;

            break;
        }
        case 3:{
            LweSample* difference = new_LweSample_array(numberofbits, in_out_params);

            full_subtractor(difference, ciphertext1, ciphertext2, numberofbits, bk, in_out_params);
            // full_subtractor(difference, ciphertext1, ciphertext2, numberofbits, key, bk, in_out_params);
            int32_t int_answer = 0;
            for (int i=0; i<numberofbits; i++) {
                int ai = bootsSymDecrypt(&difference[i], key);
                int_answer |= (ai<<i);
            }
            
            cout << "subtraction int_answer = " << int_answer << endl;
            break;
        }
        case 4:{
            LweSample *comp = new_LweSample(in_out_params);
            comparison_MUX(comp, ciphertext1, ciphertext2, numberofbits, bk, in_out_params);

            // verification
            {
                // bool messCarry = 1;
                // for (int32_t i = 0; i < numberofbits; ++i) {
                //     bool messX = bootsSymDecrypt(x + i, key);
                //     bool messY = bootsSymDecrypt(y + i, key);

                //     messCarry = (messX ^ messY) ? messY : messCarry;
                // }
                bool messComp = bootsSymDecrypt(comp, key);
                cout << "messComp = " << messComp << endl;
                // if (messComp != messCarry) {
                //     cout << "ERROR!!! " << trial << "," << nb_bits << endl;
                // }
            }
            break;
        }
        case 5: {
            LweSample* sum = new_LweSample_array(numberofbits + 1, in_out_params);
            full_adder_MUX(sum, ciphertext1, ciphertext2, numberofbits, key);
            //decrypt and rebuild the 32-bit plaintext answer
            int32_t int_answer = 0;
            for (int i=0; i<(numberofbits+1); i++) {
                int ai = bootsSymDecrypt(&sum[i], key);
                int_answer |= (ai<<i);
            }
            
            cout << "addition int_answer = " << int_answer << endl;
            break;
        }
        case 6: {
            double arg1 = stod(argv[1]);
            double arg2 = stod(argv[2]);

            cout << "arg1 = " << arg1 << endl;
            cout << "arg2 = " << arg2 << endl;
            
            double integral1, integral2;
            int integralint1, integralint2;
            double fractional1 = modf(arg1, &integral1);
            double fractional2 = modf(arg2, &integral2);
            integralint1 = integral1;
            integralint2 = integral2;
            cout << "integralint1 = " << integralint1 << endl;
            cout << "fractional1 = " << fractional1 << endl;
            cout << "integralint2 = " << integralint2 << endl;
            cout << "fractional2 = " << fractional2 << endl;
            LweSample *integerpart1 = new_gate_bootstrapping_ciphertext_array(integerbitsize,params);
            LweSample *fractionpart1 = new_gate_bootstrapping_ciphertext_array(fractionbitsize,params);
            LweSample *integerpart2 = new_gate_bootstrapping_ciphertext_array(integerbitsize,params);
            LweSample *fractionpart2 = new_gate_bootstrapping_ciphertext_array(fractionbitsize,params);
            Double temp1, temp2;
            integerpart1 = encryptIntegerpart(integralint1, key);
            // fractionpart = encryptFractionpart(128, key);
            fractionpart1 = encryptFractionpart(fractional1, key);
            // int result = decryptIntegerpart(integerpart, key);
            // cout << "integerpart decrypted result = " << result << endl;
            integerpart2 = encryptIntegerpart(integralint2, key);
            // fractionpart = encryptFractionpart(128, key);
            fractionpart2 = encryptFractionpart(fractional2, key);
            int result2 = decryptIntegerpart(integerpart2, key);
            cout << "integerpart2 decrypted result = " << result2 << endl;
            double fractionresult2 = decryptFractionpart(fractionpart2, key);
            cout << "fractionpart2 decrypted result = " << fractionresult2 << endl;
            temp1.integerpart = integerpart1;
            temp1.fractionpart = fractionpart1;
            temp2.integerpart = integerpart2;
            temp2.fractionpart = fractionpart2;
            // double decrypted = decryptDouble(temp1, key);
            // cout << "decrypted  = " << decrypted << endl;


            Double sum = full_adder_double(temp1, temp2 , &key->cloud, in_out_params, key);
            double decryptedsum = decryptDouble(sum, key);
            cout << "decryptedsum  = " << decryptedsum << endl;
            break;
        }
        case 7: {
            double arg1 = stod(argv[1]);
            double arg2 = stod(argv[2]);

            cout << "arg1 = " << arg1 << endl;
            cout << "arg2 = " << arg2 << endl;
            
            double integral1, integral2;
            int integralint1, integralint2;
            double fractional1 = modf(arg1, &integral1);
            double fractional2 = modf(arg2, &integral2);
            integralint1 = integral1;
            integralint2 = integral2;
            cout << "integralint1 = " << integralint1 << endl;
            cout << "fractional1 = " << fractional1 << endl;
            cout << "integralint2 = " << integralint2 << endl;
            cout << "fractional2 = " << fractional2 << endl;

            LweSample *integerpart1 = new_gate_bootstrapping_ciphertext_array(integerbitsize,params);
            LweSample *fractionpart1 = new_gate_bootstrapping_ciphertext_array(fractionbitsize,params);
            LweSample *integerpart2 = new_gate_bootstrapping_ciphertext_array(integerbitsize,params);
            LweSample *fractionpart2 = new_gate_bootstrapping_ciphertext_array(fractionbitsize,params);
            Double temp1, temp2;
            integerpart1 = encryptIntegerpart(integralint1, key);
            // fractionpart = encryptFractionpart(128, key);
            fractionpart1 = encryptFractionpart(fractional1, key);
            // int result = decryptIntegerpart(integerpart, key);
            // cout << "integerpart decrypted result = " << result << endl;
            integerpart2 = encryptIntegerpart(integralint2, key);
            // fractionpart = encryptFractionpart(128, key);
            fractionpart2 = encryptFractionpart(fractional2, key);
            // int result = decryptIntegerpart(integerpart1, key);
            // cout << "integerpart decrypted result = " << result << endl;
            // double fractionresult = decryptFractionpart(fractionpart1, key);
            // cout << "fractionpart1 decrypted result = " << fractionresult << endl;
            temp1.integerpart = integerpart1;
            temp1.fractionpart = fractionpart1;
            temp2.integerpart = integerpart2;
            temp2.fractionpart = fractionpart2;
            // double decrypted = decryptDouble(temp1, key);
            // cout << "decrypted  = " << decrypted << endl;


            Double difference = full_subtractor_double(temp1, temp2 , &key->cloud, in_out_params, key);
            double decrypteddiff = decryptDouble(difference, key);
            cout << "decrypteddiff  = " << decrypteddiff << endl;
            break;
        }
        case 8: {
            double arg1 = stod(argv[1]);

            Double encrypted = encryptDouble(arg1, key);
            double decrypted = decryptDouble(encrypted,key);
            cout << "decrypted = " << decrypted << endl;
            break;
        }
        case 9: {
            double arg1 = stod(argv[1]);
            double arg2 = stod(argv[2]);

            cout << "arg1 = " << arg1 << endl;
            cout << "arg2 = " << arg2 << endl;
            
            double integral1, integral2;
            int integralint1, integralint2;
            double fractional1 = modf(arg1, &integral1);
            double fractional2 = modf(arg2, &integral2);
            integralint1 = integral1;
            integralint2 = integral2;
            cout << "integralint1 = " << integralint1 << endl;
            cout << "fractional1 = " << fractional1 << endl;
            cout << "integralint2 = " << integralint2 << endl;
            cout << "fractional2 = " << fractional2 << endl;

            LweSample *integerpart1 = new_gate_bootstrapping_ciphertext_array(integerbitsize,params);
            LweSample *fractionpart1 = new_gate_bootstrapping_ciphertext_array(fractionbitsize,params);
            LweSample *integerpart2 = new_gate_bootstrapping_ciphertext_array(integerbitsize,params);
            LweSample *fractionpart2 = new_gate_bootstrapping_ciphertext_array(fractionbitsize,params);
            Double temp1, temp2;
            integerpart1 = encryptIntegerpart(integralint1, key);
            // fractionpart = encryptFractionpart(128, key);
            fractionpart1 = encryptFractionpart(fractional1, key);
            // int result = decryptIntegerpart(integerpart, key);
            // cout << "integerpart decrypted result = " << result << endl;
            integerpart2 = encryptIntegerpart(integralint2, key);
            // fractionpart = encryptFractionpart(128, key);
            fractionpart2 = encryptFractionpart(fractional2, key);
            // int result = decryptIntegerpart(integerpart1, key);
            // cout << "integerpart decrypted result = " << result << endl;
            // double fractionresult = decryptFractionpart(fractionpart1, key);
            // cout << "fractionpart1 decrypted result = " << fractionresult << endl;
            temp1.integerpart = integerpart1;
            temp1.fractionpart = fractionpart1;
            temp2.integerpart = integerpart2;
            temp2.fractionpart = fractionpart2;
            // double decrypted = decryptDouble(temp1, key);
            // cout << "decrypted  = " << decrypted << endl;

            LweSample *comp = new_LweSample(in_out_params);
            comparison_MUX_double(comp, temp1, temp2, integerbitsize + fractionbitsize, bk, in_out_params);

            // verification
            {
                // bool messCarry = 1;
                // for (int32_t i = 0; i < numberofbits; ++i) {
                //     bool messX = bootsSymDecrypt(x + i, key);
                //     bool messY = bootsSymDecrypt(y + i, key);

                //     messCarry = (messX ^ messY) ? messY : messCarry;
                // }
                bool messComp = bootsSymDecrypt(comp, key);
                cout << "messComp = " << messComp << endl;
                // if (messComp != messCarry) {
                //     cout << "ERROR!!! " << trial << "," << nb_bits << endl;
                // }
            }
            break;
        }
        case 10: {
            double arg1 = stod(argv[1]);
            double arg2 = stod(argv[2]);

            cout << "arg1 = " << arg1 << endl;
            cout << "arg2 = " << arg2 << endl;
            
            double integral1, integral2;
            int integralint1, integralint2;
            double fractional1 = modf(arg1, &integral1);
            double fractional2 = modf(arg2, &integral2);
            integralint1 = integral1;
            integralint2 = integral2;
            cout << "integralint1 = " << integralint1 << endl;
            cout << "fractional1 = " << fractional1 << endl;
            cout << "integralint2 = " << integralint2 << endl;
            cout << "fractional2 = " << fractional2 << endl;

            LweSample *integerpart1 = new_gate_bootstrapping_ciphertext_array(integerbitsize,params);
            LweSample *fractionpart1 = new_gate_bootstrapping_ciphertext_array(fractionbitsize,params);
            LweSample *integerpart2 = new_gate_bootstrapping_ciphertext_array(integerbitsize,params);
            LweSample *fractionpart2 = new_gate_bootstrapping_ciphertext_array(fractionbitsize,params);
            Double temp1, temp2, product;
            integerpart1 = encryptIntegerpart(integralint1, key);
            // fractionpart = encryptFractionpart(128, key);
            fractionpart1 = encryptFractionpart(fractional1, key);
            // int result = decryptIntegerpart(integerpart, key);
            // cout << "integerpart decrypted result = " << result << endl;
            integerpart2 = encryptIntegerpart(integralint2, key);
            // fractionpart = encryptFractionpart(128, key);
            fractionpart2 = encryptFractionpart(fractional2, key);
            // int result = decryptIntegerpart(integerpart1, key);
            // cout << "integerpart decrypted result = " << result << endl;
            // double fractionresult = decryptFractionpart(fractionpart1, key);
            // cout << "fractionpart1 decrypted result = " << fractionresult << endl;
            temp1.integerpart = integerpart1;
            temp1.fractionpart = fractionpart1;
            temp2.integerpart = integerpart2;
            temp2.fractionpart = fractionpart2;

            product = full_multiplicator_double(temp1, temp2, numberofbits, bk, in_out_params, key);
            double decrypted = decryptDouble(product,key);
            cout << "decrypted = " << decrypted << endl;
            break;

        }
        case 11: {

            int numfeatures = 16;
            Double vector1[numfeatures];
            Double vector2[numfeatures];
            // Double encrypted1 = encryptDouble(58.32, key);
            // Double encrypted2 = encryptDouble(68.06, key);

            double plainvector1[] = {53.1774257887016, 58.3208527734925, 53.8796564513203, 36.5960038381320, 49.8210980938997, 53.8630255513049, 49.7688832307925, 74.8197763989799, 61.9841652189530, 61.2600609794759, 70.4422591297480, 62.1370938283494, 47.9060076431539, 47.0480624552814, 44.9931183004167, 68.0383262878939};
            double plainvector2[] = {68.5197817927425, 68.0657482642345, 63.8217783506839, 55.0384531673322, 55.8470171682608, 54.0667840605675, 54.2067732520960, 66.0898527665596, 83.8977193079839, 94.8085760155773, 88.6278863364581, 101.820709779395, 86.6662657635354, 70.9965937618794, 63.6804273434945, 74.4111681799650};
            

            // double plainvector1[] = {2.5, 5.75};
            // double plainvector2[] = {3.25, 2.25};
            
            for (int i=0; i < numfeatures; i++){
                Double thisdouble1 = encryptDouble(plainvector1[i], key);
                Double thisdouble2 = encryptDouble(plainvector2[i], key);
                vector1[i] = thisdouble1;
                vector2[i] = thisdouble2;
            }  
            // Double encrypted1 = encryptDouble(4.75, key);
            // Double encrypted2 = encryptDouble(3.25, key);
            // vector1[0] = encrypted1;
            // vector2[0] = encrypted2;

            Double result = euclidean(vector1, vector2, numfeatures, numberofbits, bk, in_out_params, key);
            double decrypted = decryptDouble(result, key);
            cout << "answer = " << decrypted << endl;


// squared Euclidean distance should return 6.8785e+03
//                     // vettore_a
//         // 53.1774257887016
// 58.3208527734925
// 53.8796564513203
// 36.5960038381320
// 49.8210980938997
// 53.8630255513049
// 49.7688832307925
// 74.8197763989799
// 61.9841652189530
// 61.2600609794759
// 70.4422591297480
// 62.1370938283494
// 47.9060076431539
// 47.0480624552814
// 44.9931183004167
// 68.0383262878939

//         //vettor_in
//         //68.5197817927425
// 68.0657482642345
// 63.8217783506839
// 55.0384531673322
// 55.8470171682608
// 54.0667840605675
// 54.2067732520960
// 66.0898527665596
// 83.8977193079839
// 94.8085760155773
// 88.6278863364581
// 101.820709779395
// 86.6662657635354
// 70.9965937618794
// 63.6804273434945
// 74.4111681799650

            break;
        }
    }



}



// #ifndef NDEBUG
// extern const TLweKey *debug_accum_key;
// extern const LweKey *debug_extract_key;
// extern const LweKey *debug_in_key;
// #endif

// int32_t main(int32_t argc, char **argv) {
// #ifndef NDEBUG
//     cout << "DEBUG MODE!" << endl;
// #endif
//     const int32_t nb_bits = 16;
//     const int32_t nb_trials = 10;

//     // generate params 
//     int32_t minimum_lambda = 100;
//     TFheGateBootstrappingParameterSet *params = new_default_gate_bootstrapping_parameters(minimum_lambda);
//     const LweParams *in_out_params = params->in_out_params;
//     // generate the secret keyset
//     TFheGateBootstrappingSecretKeySet *keyset = new_random_gate_bootstrapping_secret_keyset(params);


//     for (int32_t trial = 0; trial < nb_trials; ++trial) {

//         // generate samples
//         LweSample *x = new_LweSample_array(nb_bits, in_out_params);
//         LweSample *y = new_LweSample_array(nb_bits, in_out_params);
//         for (int32_t i = 0; i < nb_bits; ++i) {
//             bootsSymEncrypt(x + i, rand() % 2, keyset);
//             bootsSymEncrypt(y + i, rand() % 2, keyset);
//         }
//         // output sum
//         LweSample *sum = new_LweSample_array(nb_bits + 1, in_out_params);



//         // evaluate the addition circuit 
//         cout << "starting bootstrapping " << nb_bits << "-bits addition circuit (FA in MUX version)...trial " << trial
//              << endl;
//         clock_t begin1 = clock();
//         full_adder_MUX(sum, x, y, nb_bits, keyset);
//         clock_t end1 = clock();
//         cout << "finished bootstrappings " << nb_bits << "-bits addition circuit (FA in MUX version)" << endl;
//         cout << "total time (microsecs)... " << (end1 - begin1) << endl;


//         // verification
//         bool messCarry = 0;
//         for (int32_t i = 0; i < nb_bits; ++i) {
//             bool messX = bootsSymDecrypt(x + i, keyset);
//             bool messY = bootsSymDecrypt(y + i, keyset);
//             bool messSum = bootsSymDecrypt(sum + i, keyset);

//             if (messSum != (messX ^ messY ^ messCarry)) {
//                 cout << "ERROR!!! " << trial << "," << i << " - ";
//                 cout << t32tod(lwePhase(x + i, keyset->lwe_key)) << " - ";
//                 cout << t32tod(lwePhase(y + i, keyset->lwe_key)) << " - ";
//                 cout << t32tod(lwePhase(sum + i, keyset->lwe_key)) << endl;
//             }

//             messCarry = messCarry ? (messX || messY) : (messX && messY);
//         }
//         bool messSum = bootsSymDecrypt(sum + nb_bits, keyset);
//         if (messSum != messCarry) {
//             cout << "ERROR!!! " << trial << "," << nb_bits << endl;
//         }





//         // evaluate the addition circuit 
//         cout << "starting bootstrapping " << nb_bits << "-bits addition circuit (FA)...trial " << trial << endl;
//         clock_t begin2 = clock();
//         full_adder(sum, x, y, nb_bits, keyset);
//         clock_t end2 = clock();
//         cout << "finished bootstrappings " << nb_bits << "-bits addition circuit (FA)" << endl;
//         cout << "total time (microsecs)... " << (end2 - begin2) << endl;


//         // verification
//         {
//             bool messCarry = 0;
//             for (int32_t i = 0; i < nb_bits; ++i) {
//                 bool messX = bootsSymDecrypt(x + i, keyset);
//                 bool messY = bootsSymDecrypt(y + i, keyset);
//                 bool messSum = bootsSymDecrypt(sum + i, keyset);

//                 if (messSum != (messX ^ messY ^ messCarry)) {
//                     cout << "ERROR!!! " << trial << "," << i << endl;
//                 }

//                 messCarry = messCarry ? (messX || messY) : (messX && messY);
//             }
//             bool messSum = bootsSymDecrypt(sum + nb_bits, keyset);
//             if (messSum != messCarry) {
//                 cout << "ERROR!!! " << trial << "," << nb_bits << endl;
//             }
//         }


//         LweSample *comp = new_LweSample(in_out_params);
//         // evaluate the addition circuit 
//         cout << "starting bootstrapping " << nb_bits << "-bits comparison...trial " << trial << endl;
//         clock_t begin3 = clock();
//         comparison_MUX(comp, x, y, nb_bits, keyset);
//         clock_t end3 = clock();
//         cout << "finished bootstrappings " << nb_bits << "-bits comparison" << endl;
//         cout << "total time (microsecs)... " << (end3 - begin3) << endl;

//         // verification
//         {
//             bool messCarry = 1;
//             for (int32_t i = 0; i < nb_bits; ++i) {
//                 bool messX = bootsSymDecrypt(x + i, keyset);
//                 bool messY = bootsSymDecrypt(y + i, keyset);

//                 messCarry = (messX ^ messY) ? messY : messCarry;
//             }
//             bool messComp = bootsSymDecrypt(comp, keyset);
//             if (messComp != messCarry) {
//                 cout << "ERROR!!! " << trial << "," << nb_bits << endl;
//             }
//         }


//         delete_LweSample_array(nb_bits + 1, sum);
//         delete_LweSample_array(nb_bits, y);
//         delete_LweSample_array(nb_bits, x);
//     }

//     delete_gate_bootstrapping_secret_keyset(keyset);
//     delete_gate_bootstrapping_parameters(params);

//     return 0;
// }