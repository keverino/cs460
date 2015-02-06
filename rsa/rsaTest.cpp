//To compile: g++ -o rsaTest rsaTest.cpp -lcryptopp -pthread
//To run the program: ./rsaTest

#include "cryptopp/files.h"
#include "cryptopp/base64.h"
#include "cryptopp/modes.h"
#include "cryptopp/osrng.h"
#include "cryptopp/rsa.h"
#include "cryptopp/sha.h"
#include <string.h>
#include <iostream>
#include <iomanip>
#include <ctime>

using namespace std;
using namespace CryptoPP;
//------------------------------------------------------------------------------
int keyLength;
string plaintext;
AutoSeededRandomPool rng;
InvertibleRSAFunction privkey;

void keyGeneration();
void sign();
void verify();
void encryption();
void print_string_hex(byte*, int);
//------------------------------------------------------------------------------
void keyGeneration()
{
	// start timer
	clock_t begin = clock();

	// generate random pool with user defined key length
	privkey.Initialize(rng, keyLength);

	Integer n = privkey.GetModulus();
	Integer p = privkey.GetPrime1();
	Integer q = privkey.GetPrime2();
	Integer d = privkey.GetPrivateExponent();
	Integer e = privkey.GetPublicExponent();

	// output details
	cout << "[n]: " << n << endl << endl
		  << "[p]: " << p << endl << endl
		  << "[q]: " << q << endl << endl
		  << "[d]: " << d << endl << endl
		  << "[e]: " << e << endl << endl;

	// save private key to a file.
	Base64Encoder privkeysink(new FileSink("privkey.txt"));
	privkey.DEREncode(privkeysink);
	privkeysink.MessageEnd();

	// save public key to a file.
	RSAFunction pubkey(privkey);
	Base64Encoder pubkeysink(new FileSink("pubkey.txt"));
	pubkey.DEREncode(pubkeysink);
	pubkeysink.MessageEnd();

	// stop timer and output time
	clock_t end = clock();
	double elapsedSecs = double(end - begin) / CLOCKS_PER_SEC;
	cout << "\n[Elapsed Time]: " << elapsedSecs <<  "s" << endl;
}//end keyGeneration
//------------------------------------------------------------------------------
void sign()
{
	string strContents = "A message to be signed";
	//FileSource("tobesigned.dat", true, new StringSink(strContents));

	AutoSeededRandomPool rng;

	//Read private key
	CryptoPP::ByteQueue bytes;
	FileSource file("privkey.txt", true, new Base64Decoder);
	file.TransferTo(bytes);
	bytes.MessageEnd();
	RSA::PrivateKey privateKey;
	privateKey.Load(bytes);

	//Sign message
	RSASSA_PKCS1v15_SHA_Signer privkey(privateKey);
	SecByteBlock sbbSignature(privkey.SignatureLength());
	privkey.SignMessage(
		rng,
		(byte const*) strContents.data(),
		strContents.size(),
		sbbSignature);

	//Save result
	FileSink sink("signed.dat");
	sink.Put((byte const*) strContents.data(), strContents.size());
	FileSink sinksig("sig.dat");
	sinksig.Put(sbbSignature, sbbSignature.size());
}//end sign()
//------------------------------------------------------------------------------
void verify()
{
	//Read public key
	CryptoPP::ByteQueue bytes;
	FileSource file("pubkey.txt", true, new Base64Decoder);
	file.TransferTo(bytes);
	bytes.MessageEnd();
	RSA::PublicKey pubKey;
	pubKey.Load(bytes);

	RSASSA_PKCS1v15_SHA_Verifier verifier(pubKey);

	//Read signed message
	string signedTxt;
	FileSource("signed.dat", true, new StringSink(signedTxt));
	string sig;
	FileSource("sig.dat", true, new StringSink(sig));

	string combined(signedTxt);
	combined.append(sig);

	//Verify signature
	try
	{
		StringSource(combined, true,
			new SignatureVerificationFilter(
				verifier, NULL,
				SignatureVerificationFilter::THROW_EXCEPTION
			)
		);
		cout << "Signature OK\n" << endl;
	}
	catch(SignatureVerificationFilter::SignatureVerificationFailed &err)
	{
		cout << err.what() << endl;
	}

}//end verify()
//------------------------------------------------------------------------------
void encryption()
{
	string cipherText, decryptedText;
	int trialNumber = 1;
	double totalTime = 0, elapsedSecs;
	clock_t begin, end;
	int counter = 50;

	cout << "[Plain Text]: " << plaintext << endl << endl;

	RSA::PrivateKey private_key(privkey);
	RSA::PublicKey public_key(privkey);

	// encryption
	cout << "Encrypting 50 times...";
	while(counter > 0)
	{
		cipherText = "";
		begin = clock();
		RSAES_OAEP_SHA_Encryptor e(public_key);
		StringSource ss1(plaintext, true, new PK_EncryptorFilter(rng, e, new StringSink(cipherText)));
		end = clock();
		elapsedSecs = double(end - begin) / CLOCKS_PER_SEC;
		totalTime += elapsedSecs;
		counter--;
		trialNumber++;
	}
	cout << "DONE" << endl;
	cout << "[Elapsed Time]: " << totalTime <<  "s" << endl;
	cout << "[Ciphered Text]: ";
	print_string_hex((byte*)cipherText.data(),cipherText.length());
	cout << endl << endl;

	// decryption
	// reset counters and timer
	counter = 50;
	trialNumber = 1;
	totalTime = 0;
	elapsedSecs = 0;
	cout << "Decrypting 50 times...";
	while(counter > 0)
	{
		decryptedText = "";
		begin = clock();
		RSAES_OAEP_SHA_Decryptor d(private_key);
		StringSource ss2(cipherText, true, new PK_DecryptorFilter(rng, d, new StringSink(decryptedText)));
		end = clock();
		elapsedSecs = double(end - begin) / CLOCKS_PER_SEC;
		totalTime += elapsedSecs;
		counter--;
		trialNumber++;
	}
	cout << "DONE";
	cout << "\n[Decrypted Text]: " << decryptedText;
	cout << "\n[Elapsed Time]: " << totalTime << "s" << endl;
}
//------------------------------------------------------------------------------
void print_string_hex(byte* in, int len)
{
	for (int i = 0; i < len; i++)
		cout << setfill('0') << setw(2) << hex << (short)in[i];
}
//------------------------------------------------------------------------------
int main()
{
	cout << "\n------Key Generation------\n";
	cout << "Please enter a key length: ";
	cin >> keyLength;
	keyGeneration();

	cout << "Signing ";
	sign();
	cout << " OK\n";

	cout << "Verify ";
	verify();

	cout << "\n------Encryption & Decryption------\n";
	cout << "Please enter plaintext to encrypt: ";
	cin >> plaintext;
	//getline(cin, plaintext);
	encryption();

	return 0;
}//end main()
//------------------------------------------------------------------------------
