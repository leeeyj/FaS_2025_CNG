#include <Windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "bcrypt.lib")

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

void Decrypt()
{
	NTSTATUS status = 0;
	//--------------------------------------------------------------------------------------------------
	BYTE Cipher[] = { 0xA6, 0xF0, 0x85, 0x61,
			  0xF2, 0xA4, 0x37, 0xC9,
			  0xD7, 0x65, 0x08, 0x0F,
			  0xB6, 0x9C, 0xBF, 0x31,
			  0xD4, 0x56, 0xC4, 0xBC,
			  0x9D, 0x7F, 0x9B, 0x4E,
			  0xA6, 0xC6, 0x46, 0xE7,
			  0x9C, 0xF4, 0xC1, 0xEE };
	BYTE* Plain = NULL;
	//--------------------------------------------------------------------------------------------------
	// AES256/CBC/PKCS7Padding 
	BYTE	iv[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

	DWORD	IVLength = 0;
	DWORD	BlockLength = 0;
	DWORD	bufferSize = 0;
	DWORD	PlainLength = 0;
	//--------------------------------------------------------------------------------------------------
	// 1. Open Algorithm Provider 
	BCRYPT_ALG_HANDLE algHandle = NULL;
	status = BCryptOpenAlgorithmProvider(
			 &algHandle,			// Address of Algorithm Handle
			 BCRYPT_AES_ALGORITHM,  // Cryptographic Algorithm Name 
			 NULL,					// Not Usze
			 0);					// Flags 
	if (!NT_SUCCESS(status)) { printf("1\n"); return; }
	//--------------------------------------------------------------------------------------------------
	// 2. Generate AES256 Key Object
	BCRYPT_KEY_HANDLE KEY_HANDLE = NULL;

	BYTE	AES256Key[32] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

	status = BCryptGenerateSymmetricKey(
			 algHandle,			// Algorithm Handle
			 &KEY_HANDLE,		// Symmetric Key Handle 
			 NULL,				// Not use
			 0,					// Not use 
			 AES256Key,			// Key 
			 sizeof(AES256Key), // Key size 
			 0);				// Flags 
	if (!NT_SUCCESS(status)) { printf("2\n"); return; }
	//--------------------------------------------------------------------------------------------------
	// 3.Setting Algorithm Properties - Operation Mode CBC 
	status = BCryptSetProperty(
			 KEY_HANDLE,					// Symmetric Key Handle 
			 BCRYPT_CHAINING_MODE,			// The name of the property to set 
			 (PBYTE)BCRYPT_CHAIN_MODE_CBC,  // Address of property value 
			 sizeof(BCRYPT_CHAIN_MODE_CBC), // Property value size 
			 0);							// Flags 
	if (!NT_SUCCESS(status)) { printf("3\n"); return; }
	//--------------------------------------------------------------------------------------------------
	// 4. Getting Algorithm Properties - IVLength = BlockLength
	status = BCryptGetProperty(
			 KEY_HANDLE,			// Symmetric Key Handle 
			 BCRYPT_BLOCK_LENGTH,	// The name of the property to obtain
			 (PBYTE)&IVLength,		// Address of buffer that receives the value
			 sizeof(DWORD),			// Size of buffer that receives the value 
			 &bufferSize,			// number of bytes that were copied to the buffer 
			 0);					// Flags 
	if (!NT_SUCCESS(status)) { printf("4\n"); return; }
	BlockLength = IVLength;
	//--------------------------------------------------------------------------------------------------
	// 5. Operate AES256/CBC/PKCS7Padding - Calculate Plaintext Length 
	status = BCryptDecrypt(
			 KEY_HANDLE,			// Symmetric Key Handle 
			 Cipher,				// Ciphertext
			 sizeof(Cipher),		// Size of Ciphertext
			 NULL,					// Not use  
			 iv,					// IV
			 IVLength,				// Size of IV
			 NULL,					// Set NULL to calculate Plaintext Length
			 0,						// 0
			 &PlainLength,			// Receives the size of Plaintext
			 BCRYPT_BLOCK_PADDING); // Flags for Padding 
	if (!NT_SUCCESS(status)) { printf("5\n"); return; }
	//--------------------------------------------------------------------------------------------------
	// 6. Operate AES256/CBC/PKCS7Padding - Decrypt Ciphertext 
	Plain = (PBYTE)calloc(PlainLength, sizeof(BYTE));
	if (Plain == NULL) return;
	status = BCryptDecrypt(
			 KEY_HANDLE,			// Symmetric Key Handle 
			 Cipher,				// Ciphertext
			 sizeof(Cipher),		// Size of Ciphertext
			 NULL,					// Not use  
			 iv,					// IV
			 IVLength,				// Size of IV
			 Plain,					// Plaintext
			 PlainLength,			// Size of Plaintext
			 &bufferSize,			// number of bytes that were copied to the buffer 
			 BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status)) { printf("6\n"); return; }
	// --------------------------------------------------------------------------------------------------
	// 7. Print Plain text
	printf("Plain: %s", Plain);
	// --------------------------------------------------------------------------------------------------
	// 8. Memory Free
	BCryptDestroyKey(KEY_HANDLE);
	BCryptCloseAlgorithmProvider(algHandle, 0);
	free(Plain);

	return;
}

int main()
{
	Decrypt();
	return 0;
}

