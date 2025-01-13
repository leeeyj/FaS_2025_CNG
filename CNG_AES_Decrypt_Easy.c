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
	// CNG Variables  
	BCRYPT_ALG_HANDLE algHandle = BCRYPT_AES_CBC_ALG_HANDLE;
	BCRYPT_KEY_HANDLE KEY_HANDLE = NULL;
	//--------------------------------------------------------------------------------------------------
	// AES256/CBC/PKCS7Padding 
	BYTE	iv[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

	BYTE	AES256Key[32] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
							  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

	DWORD	IVLength = 16;
	DWORD	BlockLength = 16;
	DWORD	bufferSize = 0;
	DWORD	PlainLength = 0;
	//--------------------------------------------------------------------------------------------------
	// 1. Generate AES256 Key Object 
	status = BCryptGenerateSymmetricKey(
			 algHandle,
			 &KEY_HANDLE,
			 NULL,
			 0,
			 AES256Key,
			 sizeof(AES256Key),
			 0);
	if (!NT_SUCCESS(status)) { printf("1\n"); return; }
	//--------------------------------------------------------------------------------------------------
	// 2. Operate AES256/CBC/PKCS7Padding - Calculate Plaintext Length 
	status = BCryptDecrypt(
			 KEY_HANDLE,
			 Cipher,
			 sizeof(Cipher),
			 NULL,
			 iv,
			 IVLength,
			 NULL,
			 0,
			 &PlainLength,
			 BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status)) { printf("2\n"); return; }
	//--------------------------------------------------------------------------------------------------
	// 3. Operate AES256/CBC/PKCS7Padding - Decrypt Ciphertext 
	Plain = (PBYTE)calloc(PlainLength, sizeof(BYTE));
	if (Plain == NULL) return;
	status = BCryptDecrypt(
			 KEY_HANDLE,
			 Cipher,
			 sizeof(Cipher),
			 NULL,
			 iv,
			 IVLength,
			 Plain,
			 PlainLength,
			 &bufferSize,
			 BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status)) { printf("3\n"); return; }
	// --------------------------------------------------------------------------------------------------
	// 4. Print Plaintext
	printf("Plain: %s", Plain);
	// --------------------------------------------------------------------------------------------------
	// 5. Memory Free
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

