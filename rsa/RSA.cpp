#include <cryptopp/files.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <cryptopp/sha.h>

void rsa_examples()
{
	// Keys created here may be used by OpenSSL.
	//
	// openssl pkcs8 -in key.der -inform DER -out key.pem -nocrypt
	// openssl rsa -in key.pem -check

	CryptoPP::AutoSeededRandomPool rng;

	// Create a private RSA key and write it to a file using DER.
	CryptoPP::RSAES_OAEP_SHA_Decryptor priv( rng, 4096 );
	CryptoPP::TransparentFilter privFile( new CryptoPP::FileSink("rsakey.der") );
	priv.DEREncode( privFile );
	privFile.MessageEnd();

	// Create a private RSA key and write it to a string using DER (also write to a file to check it with OpenSSL).
	std::string the_key;
	CryptoPP::RSAES_OAEP_SHA_Decryptor pri( rng, 2048 );
	CryptoPP::TransparentFilter privSink( new CryptoPP::StringSink(the_key) );
	pri.DEREncode( privSink );
	privSink.MessageEnd();

	std::ofstream file ( "key.der", std::ios::out | std::ios::binary );
	file.write( the_key.data(), the_key.size() );
	file.close();

	// Example Encryption & Decryption
	CryptoPP::InvertibleRSAFunction params;
	params.GenerateRandomWithKeySize( rng, 1536 );

	std::string plain = "RSA Encryption", cipher, decrypted_data;

	CryptoPP::RSA::PrivateKey privateKey( params );
	CryptoPP::RSA::PublicKey publicKey( params );

	CryptoPP::RSAES_OAEP_SHA_Encryptor e( publicKey );
	CryptoPP::StringSource( plain, true, new CryptoPP::PK_EncryptorFilter( rng, e, new CryptoPP::StringSink( cipher )));

	CryptoPP::RSAES_OAEP_SHA_Decryptor d( privateKey );
	CryptoPP::StringSource( cipher, true, new CryptoPP::PK_DecryptorFilter( rng, d, new CryptoPP::StringSink( decrypted_data )));

	assert( plain == decrypted_data );
}
