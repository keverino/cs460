#include <iostream>
using std::cout;
using std::endl;
#include "cryptopp/integer.h"
using CryptoPP::Integer;

int main( int, char** )
{
	Integer i("123");
	cout << "The integer i is " << i << endl;
	return 0;
}
