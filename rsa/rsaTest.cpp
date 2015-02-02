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

int main()
{
	int keyLength;

	cout << "Please enter a key length:\n";
	cin >> keyLength;
	cout << "You entered\n" << keyLength << endl;
	return 0;
}
