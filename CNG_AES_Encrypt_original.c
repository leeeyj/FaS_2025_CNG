#include <Windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "bcrypt.lib")

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

void Encrypt()
{
	NTSTATUS status = 0; 

	//--------------------------------------------------------------------------------------------------
	BYTE Plain[] = { 'F', 'a', 'S', ' ', '2', '0', '2', '5', ' ',
			 'F', 'a', 'S', ' ', '2', '0', '2', '5', ' ',
			 'F', 'a', 'S', ' ', '2', '0', '2', '5', '\0' };
	BYTE* Cipher = NULL;	
	printf("Plain text: %s\n", Plain);
	//--------------------------------------------------------------------------------------------------
	// AES256/CBC/PKCS7Padding 
	BYTE	iv[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	
	DWORD	IVLength		= 0;	
	DWORD	BlockLength		= 0;	
	DWORD	bufferSize		= 0;	
	DWORD	CipherLength		= 0;
	//--------------------------------------------------------------------------------------------------
	// 1. Open Algorithm Provider 
	BCRYPT_ALG_HANDLE algHandle = NULL;
	status = BCryptOpenAlgorithmProvider(
			 &algHandle,			// Address of Algorithm Handle
			 BCRYPT_AES_ALGORITHM, 		// Cryptographic Algorithm Name 
			 NULL,				// Not Usze
			 0);				// Flags 
	if (!NT_SUCCESS(status)) { printf("1\n"); return; } 
	//--------------------------------------------------------------------------------------------------
	// 2. Generate AES256 Key Object
	BCRYPT_KEY_HANDLE KEY_HANDLE	= NULL; 
	
	BYTE	AES256Key[32] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

	status = BCryptGenerateSymmetricKey(
			 algHandle,			// Algorithm Handle
			 &KEY_HANDLE,			// Symmetric Key Handle 
			 NULL,				// Not use
			 0,				// Not use 
			 AES256Key,			// Key 
			 sizeof(AES256Key), 		// Key size 
			 0);				// Flags 
	if (!NT_SUCCESS(status)) { printf("2\n"); return; }
	//--------------------------------------------------------------------------------------------------
	// 3.Setting Algorithm Properties - Operation Mode CBC 
	status = BCryptSetProperty(
			 KEY_HANDLE,				// Symmetric Key Handle 
			 BCRYPT_CHAINING_MODE,			// The name of the property to set 
			 (PBYTE)BCRYPT_CHAIN_MODE_CBC,  	// Address of property value 
			 sizeof(BCRYPT_CHAIN_MODE_CBC), 	// Property value size 
			 0);					// Flags 
	if (!NT_SUCCESS(status)) { printf("3\n"); return; }
	//--------------------------------------------------------------------------------------------------
	// 4. Getting Algorithm Properties - IVLength = BlockLength
	status = BCryptGetProperty(
			 KEY_HANDLE,			// Symmetric Key Handle 
			 BCRYPT_BLOCK_LENGTH,		// The name of the property to obtain
			 (PBYTE)&IVLength,		// Address of buffer that receives the value
			 sizeof(DWORD),			// Size of buffer that receives the value 
			 &bufferSize,			// number of bytes that were copied to the buffer 
			 0);				// Flags 
	if (!NT_SUCCESS(status)) { printf("4\n"); return; }
	BlockLength = IVLength;
	//--------------------------------------------------------------------------------------------------
	// 5. Operate AES256/CBC/PKCS7Padding - Calculate Ciphertext Length 
	status = BCryptEncrypt(
			 KEY_HANDLE,			// Symmetric Key Handle 
			 Plain,				// Plaintext
			 sizeof(Plain),			// Size of Plaintext
			 NULL,				// Not use  
			 iv,				// IV
			 IVLength,			// Size of IV
			 NULL,				// Set NULL to calculate Ciphertext Length
			 0,				// 0
			 &CipherLength,			// Receives the size of Ciphertext
			 BCRYPT_BLOCK_PADDING); 	// Flags for Padding 
	if (!NT_SUCCESS(status)) { printf("5\n"); return; }
	//--------------------------------------------------------------------------------------------------
	// 6. Operate AES256/CBC/PKCS7Padding - Encrypt Plain text 
	Cipher = (PBYTE)calloc(CipherLength, sizeof(BYTE));
	if (Cipher == NULL) return; 
	status = BCryptEncrypt(
			 KEY_HANDLE,			// Symmetric Key Handle 
			 Plain,				// Plaintext
			 sizeof(Plain),			// Size of Plaintext
			 NULL,				// Not use  
			 iv,				// IV
			 IVLength,			// Size of IV
			 Cipher,			// Ciphertext
			 CipherLength,			// Size of Ciphertext
			 &bufferSize,			// number of bytes that were copied to the buffer 
			 BCRYPT_BLOCK_PADDING);		// Flags
	if (!NT_SUCCESS(status)) { printf("6\n"); return; }
	// --------------------------------------------------------------------------------------------------
	// 7. Print Cipher text
	printf("Cipher: ");
	for (int i = 0; i < CipherLength; i++) printf("0x%02X, ", Cipher[i]);
	// --------------------------------------------------------------------------------------------------
	// 8. Memory Free
	BCryptDestroyKey(KEY_HANDLE);
	BCryptCloseAlgorithmProvider(algHandle, 0);
	free(Cipher);

	return; 
}

int main()
{
	Encrypt();

	return 0;
}

