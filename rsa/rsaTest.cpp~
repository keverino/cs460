#include "files.h"
#include "modes.h"
#include "osrng.h"
#include "rsa.h"
#include "sha.h"
#include <string.h>
#include <iostream>
#include <iomanip>

using namespace std;
using namespace CryptoPP;

void keyGeneration();
void encryption();
void print_string_hex(byte*, int);

void keyGeneration()
{
	AutoSeededRandomPool rng;
	InvertibleRSAFunction params;
	params.GenerateRandomWithKeySize(rng, 3072);
	Integer n=params.GetModulus();
	Integer p=params.GetPrime1();
	Integer q=params.GetPrime2();
	Integer d=params.GetPrivateExponent();
	Integer e=params.GetPublicExponent();
	cout << "n=" << n << endl 
		  << "p=" << p << endl
		  << "q=" << q << endl
		  << "d=" << d << endl
		  << "e=" << e << endl;
}

int main()
{
	int keyLength;

	cout << "Please enter a key length:\n";
	cin >> keyLength;
	cout << "You entered\n" << keyLength << endl;

	cout << "Generating key";
	keyGeneration();

	return 0;
}
