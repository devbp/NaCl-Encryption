// NaclEncryption.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "crypto_box.h"
#include <string>
#include <iostream>
#include <fstream>
#include <time.h>
#include "crypto_sign.h"

#include "crypto_box_curve25519xsalsa20poly1305.h"
#include "crypto_sign_edwards25519sha512batch.h"
#include "randombytes.h"
/*
unsigned char alicesk[32] = {
	0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d
	, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45
	, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a
	, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
};

unsigned char bobpk[32] = {
	0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4
	, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37
	, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d
	, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
};
unsigned char nonce[24] = {
	0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73
	, 0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6
	, 0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37
};


unsigned char m[163] = {
	0, 0, 0, 0, 0, 0, 0, 0
	, 0, 0, 0, 0, 0, 0, 0, 0
	, 0, 0, 0, 0, 0, 0, 0, 0
	, 0, 0, 0, 0, 0, 0, 0, 0
	, 0xbe, 0x07, 0x5f, 0xc5, 0x3c, 0x81, 0xf2, 0xd5
	, 0xcf, 0x14, 0x13, 0x16, 0xeb, 0xeb, 0x0c, 0x7b
	, 0x52, 0x28, 0xc5, 0x2a, 0x4c, 0x62, 0xcb, 0xd4
	, 0x4b, 0x66, 0x84, 0x9b, 0x64, 0x24, 0x4f, 0xfc
	, 0xe5, 0xec, 0xba, 0xaf, 0x33, 0xbd, 0x75, 0x1a
	, 0x1a, 0xc7, 0x28, 0xd4, 0x5e, 0x6c, 0x61, 0x29
	, 0x6c, 0xdc, 0x3c, 0x01, 0x23, 0x35, 0x61, 0xf4
	, 0x1d, 0xb6, 0x6c, 0xce, 0x31, 0x4a, 0xdb, 0x31
	, 0x0e, 0x3b, 0xe8, 0x25, 0x0c, 0x46, 0xf0, 0x6d
	, 0xce, 0xea, 0x3a, 0x7f, 0xa1, 0x34, 0x80, 0x57
	, 0xe2, 0xf6, 0x55, 0x6a, 0xd6, 0xb1, 0x31, 0x8a
	, 0x02, 0x4a, 0x83, 0x8f, 0x21, 0xaf, 0x1f, 0xde
	, 0x04, 0x89, 0x77, 0xeb, 0x48, 0xf5, 0x9f, 0xfd
	, 0x49, 0x24, 0xca, 0x1c, 0x60, 0x90, 0x2e, 0x52
	, 0xf0, 0xa0, 0x89, 0xbc, 0x76, 0x89, 0x70, 0x40
	, 0xe0, 0x82, 0xf9, 0x37, 0x76, 0x38, 0x48, 0x64
	, 0x5e, 0x07, 0x05
};


unsigned char bobsk[32] = {
	0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b
	, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6
	, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd
	, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb
};
unsigned char alicepk[32] = {
	0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54
	, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a
	, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4
	, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a
};


unsigned char c[163];

unsigned char cipher[163] = {
	0, 0, 0, 0, 0, 0, 0, 0
	, 0, 0, 0, 0, 0, 0, 0, 0
	, 0xf3, 0xff, 0xc7, 0x70, 0x3f, 0x94, 0x00, 0xe5
	, 0x2a, 0x7d, 0xfb, 0x4b, 0x3d, 0x33, 0x05, 0xd9
	, 0x8e, 0x99, 0x3b, 0x9f, 0x48, 0x68, 0x12, 0x73
	, 0xc2, 0x96, 0x50, 0xba, 0x32, 0xfc, 0x76, 0xce
	, 0x48, 0x33, 0x2e, 0xa7, 0x16, 0x4d, 0x96, 0xa4
	, 0x47, 0x6f, 0xb8, 0xc5, 0x31, 0xa1, 0x18, 0x6a
	, 0xc0, 0xdf, 0xc1, 0x7c, 0x98, 0xdc, 0xe8, 0x7b
	, 0x4d, 0xa7, 0xf0, 0x11, 0xec, 0x48, 0xc9, 0x72
	, 0x71, 0xd2, 0xc2, 0x0f, 0x9b, 0x92, 0x8f, 0xe2
	, 0x27, 0x0d, 0x6f, 0xb8, 0x63, 0xd5, 0x17, 0x38
	, 0xb4, 0x8e, 0xee, 0xe3, 0x14, 0xa7, 0xcc, 0x8a
	, 0xb9, 0x32, 0x16, 0x45, 0x48, 0xe5, 0x26, 0xae
	, 0x90, 0x22, 0x43, 0x68, 0x51, 0x7a, 0xcf, 0xea
	, 0xbd, 0x6b, 0xb3, 0x73, 0x2b, 0xc0, 0xe9, 0xda
	, 0x99, 0x83, 0x2b, 0x61, 0xca, 0x01, 0xb6, 0xde
	, 0x56, 0x24, 0x4a, 0x9e, 0x88, 0xd5, 0xf9, 0xb3
	, 0x79, 0x73, 0xf6, 0x22, 0xa4, 0x3d, 0x14, 0xa6
	, 0x59, 0x9b, 0x1f, 0x65, 0x4c, 0xb4, 0x5a, 0x74
	, 0xe3, 0x55, 0xa5
};



void encryptandauthenciate()
{
	crypto_box_curve25519xsalsa20poly1305(c, m, 163, nonce, bobpk, alicesk);

}

void decrypt()
{
	crypto_box_curve25519xsalsa20poly1305_open(m, cipher, 163, nonce, alicepk, bobsk);

}
*/

/*

unsigned char nonce[24] = {
	0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73
	, 0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6
	, 0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37
};
*/
unsigned char nonce[24];

void WriteBinaryFile(std::string filename, unsigned char* buffer, long size)
{
    //long size1 = std::string(buffer).length();
	std::ofstream writefile;
	try
	{
		writefile.open(filename, std::ios::out | std::ios::binary);
		if (writefile.is_open() == 0)
			throw  std::exception("cannot read file");
	}
	catch (std::exception ex)
	{
		std::cout << "error opening the file";
	}
	writefile.write((char*)buffer, size);
	writefile.close();
	std::cout << "file written can closed";
}


unsigned char* ReadinBinayFormat(std::string filename, long &buffersize)
{		std::ifstream data;
		unsigned char *buffer;

		data.open(filename, std::ios::in | std::ios::binary);
		if (data.is_open() == 0)
		throw  std::exception("cannot read file");

	//go to the end of the file
	data.seekg(0, std::ios::end);
	//get the size of the file
	buffersize = (long)data.tellg();
	std::cout << "size of the file is" << buffersize << "bytes" << std::endl;
	//go to the beginning of the file
	data.seekg(0, std::ios::beg);
	//allocate the memory for the data to store
	buffer = new unsigned char[buffersize];
	//read the whole file 
	data.read((char*)(buffer), buffersize);
	//std::cout <<"Read data="<< buffer_data[9];
	data.close();
	return buffer;

}

unsigned char *original_msg;
long filesize;


//function to encrypt and Decrypt using curve25519
void EncryptandDecrypt()
{
	unsigned char alicepublickey[crypto_box_PUBLICKEYBYTES];
	unsigned char alicesecretkey[crypto_box_SECRETKEYBYTES];
	unsigned char bobpublickey[crypto_box_PUBLICKEYBYTES];
	unsigned char bobsecretkey[crypto_box_SECRETKEYBYTES];
	//generate 32 bits public and private keys for both parties
	crypto_box_curve25519xsalsa20poly1305_keypair(alicepublickey, alicesecretkey);
	crypto_box_curve25519xsalsa20poly1305_keypair(bobpublickey, bobsecretkey);
	
	//crypto_box_keypair(alicepublickey, alicesecretkey);
	//crypto_box_keypair(bobpublickey, bobsecretkey);
	//just print the keys for the test
	for (int i = 0; i < crypto_box_PUBLICKEYBYTES; i++)
		printf(",0x%02x", (unsigned int)alicepublickey[i]);


	//generate 24 bytes of nonce randomly
	randombytes(nonce,24);
	

	original_msg = ReadinBinayFormat("image.JPG", filesize);
	//original_msg = realloc();
	//original_msg = (unsigned char*)realloc(original_msg, filesize + 32);
	unsigned char *cipher_msg;
	unsigned char *decrypted_msg;
	unsigned char *paddedmessage;
	//we add 32 because we pad the message with 32 zeros at the beginning of the message
	paddedmessage = new unsigned char[filesize + 32];
	//the cipher text will have 16 zeros at the beginning i.e total length of actual cipher is filesize+16
	cipher_msg = new unsigned char[filesize + 32];
	//decrypted message will have again 32 zeros at the beginning of the message
	decrypted_msg = new unsigned char[filesize + 32];
	unsigned char *decrypted_padremovedmsg;
	decrypted_padremovedmsg = new unsigned char[filesize];


	//here we should add 32 zeros at the beginning of the message
	clock_t padstarttime = clock();
	for (int i = 0; i < 32; i++)
		paddedmessage[i] = 0x00;

	int j = 0;
	//append the messages
	for (int i = 32; i < filesize + 32; i++, j++)
		paddedmessage[i] = original_msg[j];
	clock_t padendtime=clock();
	std::cout << "Message padding time" << (double)(padendtime - padstarttime) / CLOCKS_PER_SEC;

	

	WriteBinaryFile("paddedmessage.bin", paddedmessage, filesize + 32);
	clock_t tstart = clock();
	clock_t end;
	//encrypt the message
	crypto_box_curve25519xsalsa20poly1305(cipher_msg, paddedmessage, filesize + 32, nonce, bobpublickey, alicesecretkey);

	std::cout << "Time for encryption =" << ((double)clock() - tstart) / CLOCKS_PER_SEC << std::endl;

	//memset(original_msg,2,12);
	// memset(original_msg, 0, 20);
	// memset(cipher_msg, 0, 20);
	//memset(decrypted_msg, 0, 20);
	// memcpy(original_msg,message,sizeof(message));
	// std::cout << original_msg[0] << std::endl<<"size"<<sizeof(original_msg)<<std::endl;
	//bob authenciates using Bobs secret key and encrypts using alice public key
	// crypto_box(cipher_msg, original_msg, filesize+32, nonce, alicepublickey, bobsecretkey);

	int cipher_msgsize = filesize + 32;

	WriteBinaryFile("encrypted.bin", cipher_msg, cipher_msgsize);

	std::cout << cipher_msg[0] << std::endl;
	long encryptedfilesize;
	cipher_msg = ReadinBinayFormat("encrypted.bin", encryptedfilesize);

	//crypto_box_open(decrypted_msg,cipher_msg,encryptedfilesize,nonce,bobpublickey,alicesecretkey);

	tstart = clock();
	//decrypt the message
	crypto_box_curve25519xsalsa20poly1305_open(decrypted_msg, cipher_msg, filesize + 32, nonce, alicepublickey, bobsecretkey);
	end = clock();
	std::cout << "Decryption time" << (double)(end-tstart) / CLOCKS_PER_SEC << std::endl;
	std::cout << decrypted_msg[0] << "size=" << sizeof(decrypted_msg) << std::endl;
	WriteBinaryFile("decrypted.bin", decrypted_msg, filesize + 32);

	j = 0;
	for (int i = 32; i < filesize + 32; i++, j++)
		decrypted_padremovedmsg[j] = decrypted_msg[i];

	WriteBinaryFile("decryptedremovedpad.jpg", decrypted_padremovedmsg, filesize);
	//long long 
}

void SignandVerify()
{
	unsigned char alicepublickey[crypto_sign_PUBLICKEYBYTES];
	unsigned char alicesecretkey[crypto_sign_SECRETKEYBYTES];
	//unsigned char bobpublickey[crypto_sign_PUBLICKEYBYTES];
	//unsigned char bobsecretkey[crypto_sign_SECRETKEYBYTES];
	unsigned char *msg_signature;
	msg_signature = new unsigned char[filesize + crypto_sign_BYTES];
	unsigned long long signature_len,messagelen;
	//crypto_sign_ed25519_keypair(alicepublickey, alicesecretkey);
	//Generate public key and private key to sign and verify
	crypto_sign_edwards25519sha512batch_keypair(alicepublickey, alicesecretkey);
	//sign the mesage with edwards25519 and sha512 hash  
	crypto_sign_edwards25519sha512batch(msg_signature, &signature_len, original_msg, filesize, alicesecretkey);
	
		//verify the message
	int s=crypto_sign_edwards25519sha512batch_open(original_msg,&messagelen,msg_signature,signature_len,alicepublickey);
	if (s == 0)
		std::cout << "signature verified";
}


int _tmain(int argc, _TCHAR* argv[])
{
	//encryptandauthenciate();
	//decrypt();
	EncryptandDecrypt();
	SignandVerify();
	//crypto_box_open()
		 system("pause");
	/*
	//unsigned char seckey[90], pubkey[90];
	std::string publickey;
	std::string secretkey;
	//const unsigned char n[crypto_box_NONCEBYTES]="1234567890qwertzuiopasdf";
	std::string n="123456789012345678901234";
	std::string message="hello world ";
	std::string cipher;

	//crypto_box_PUBLICKEYBYTES
	//crypto_box_keypair(seckey,pubkey);
	int status = crypto_box_keypair(((unsigned char*)publickey.c_str()), ((unsigned char*)secretkey.c_str()));
	std::cout << publickey.size()<<std::endl;
	std::cout << message.size();
	//crypto_box((unsigned char*)cipher.c_str(), (unsigned char*)message.c_str(), message.length(),(unsigned char*)n.c_str(),  (unsigned char*)publickey.c_str(), (unsigned char*)secretkey.c_str());
	system("pause");
	return 0;
	*/
}

