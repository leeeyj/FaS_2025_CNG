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
	
	BYTE Plain[] = { 'F', 'a', 'S', ' ', '2', '0', '2', '5', ' ',
			 'F', 'a', 'S', ' ', '2', '0', '2', '5', ' ',
			 'F', 'a', 'S', ' ', '2', '0', '2', '5', '\0' };
	
	BYTE* Cipher = NULL;

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
	DWORD	CipherLength = 0;
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
	// 2. Operate AES256/CBC/PKCS7Padding - Calculate Ciphertext Length 
	status = BCryptEncrypt(
			 KEY_HANDLE,
			 Plain,
			 sizeof(Plain),
			 NULL,
			 iv,
			 IVLength,
			 NULL,
			 0,
			 &CipherLength,
			 BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status)) { printf("2\n"); return; }
	//--------------------------------------------------------------------------------------------------
	// 3. Operate AES256/CBC/PKCS7Padding - Encrypt Plain text 
	Cipher = (PBYTE)calloc(CipherLength, sizeof(BYTE));
	if (Cipher == NULL) return;
	status = BCryptEncrypt(
			 KEY_HANDLE,
			 Plain,
			 sizeof(Plain),
			 NULL,
			 iv,
			 IVLength,
			 Cipher,
			 CipherLength,
			 &bufferSize,
			 BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status)) { printf("3\n"); return; }
	// --------------------------------------------------------------------------------------------------
	// 4. Print Cipher text
	printf("Cipher: ");
	for (int i = 0; i < CipherLength; i++) printf("%02X ", Cipher[i]);
	// --------------------------------------------------------------------------------------------------
	// 5. Memory Free
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

