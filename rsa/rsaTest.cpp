//To compile: g++ -o rsaTest rsaTest.cpp -lcryptopp -pthread
//To run the program: ./rsaTest

#include "files.h"
#include "base64.h"
#include "modes.h"
#include "osrng.h"
#include "rsa.h"
#include "sha.h"
#include <string.h>
#include <iostream>
#include <iomanip>

using namespace std;
using namespace CryptoPP;
//------------------------------------------------------------------------------
int keyLength;
string plaintext;

void keyGeneration();
void sign();
void verify();
void encryption();
void print_string_hex(byte*, int);
//------------------------------------------------------------------------------
void keyGeneration()
{
	// generate random pool with user defined key length
	AutoSeededRandomPool rng;
	InvertibleRSAFunction privkey;
	privkey.Initialize(rng, keyLength);

	Integer n = privkey.GetModulus();
	Integer p = privkey.GetPrime1();
	Integer q = privkey.GetPrime2();
	Integer d = privkey.GetPrivateExponent();
	Integer e = privkey.GetPublicExponent();

	cout << "n: " << n << endl << endl
		  << "p: " << p << endl << endl
		  << "q: " << q << endl << endl
		  << "d: " << d << endl << endl
		  << "e: " << e << endl << endl;

	// save private key to a file.
	Base64Encoder privkeysink(new FileSink("privkey.txt"));
	privkey.DEREncode(privkeysink);
	privkeysink.MessageEnd();

	// save public key to a file.
	RSAFunction pubkey(privkey);
	Base64Encoder pubkeysink(new FileSink("pubkey.txt"));
	pubkey.DEREncode(pubkeysink);
	pubkeysink.MessageEnd();
}
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
}
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

}
//------------------------------------------------------------------------------
void encryption()
{
	string cipherText, decryptedText;

	AutoSeededRandomPool rng;
	InvertibleRSAFunction params;
	params.GenerateRandomWithKeySize(rng, keyLength);
	RSA::PrivateKey private_key(params);
	RSA::PublicKey public_key(params);

	RSAES_OAEP_SHA_Encryptor e(public_key);
	StringSource ss1(plaintext, true, new PK_EncryptorFilter(rng, e, new StringSink(cipherText)));
	RSAES_OAEP_SHA_Decryptor d(private_key);
	StringSource ss2(cipherText, true, new PK_DecryptorFilter(rng, d, new StringSink(decryptedText)));
	cout << "Plain Text: " << plaintext << endl << endl;
	cout << "Ciphered Text: ";
	print_string_hex((byte*)cipherText.data(),cipherText.length());
	cout << endl << endl;
	cout << "Decrypted Text: " << decryptedText << endl;
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
	cout << "Please enter a key length: ";
	cin >> keyLength;

	cout << "\n------Generating keys------\n";
	keyGeneration();

	cout << "Signing\n";
	sign();

	cout << "Verifiying\n";
	verify();

	cout << "Please enter plaintext to encrypt: ";
	cin >> plaintext;

	cout << "\n------Encryption & Decryption------\n";
	encryption();

	return 0;
}
//------------------------------------------------------------------------------
