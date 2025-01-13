#include <Windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "bcrypt.lib")

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

int main()
{
	NTSTATUS status;
	BCRYPT_ALG_HANDLE algHandle = NULL;	// Algorithm Handle 

	// Open Algorithm Provider - RNG
	status = BCryptOpenAlgorithmProvider(
			 &algHandle,				// Address of Algorithm Handle
			 BCRYPT_RNG_ALGORITHM,		// Cryptographic Algorithm Name 
			 NULL,						// Not use
			 0);						// Flags 
	if (!NT_SUCCESS(status)) return;	// Print Error Code

	// Performing Cryptographic Operations 
	BYTE random[16] = { 0, };
	status = BCryptGenRandom(
			 algHandle,							// Algorithm Handle 
			 random,							// Address of a buffer that receives the random number
			 16,								// The size of the random
			 BCRYPT_RNG_USE_ENTROPY_IN_BUFFER); // Flags
	if (!NT_SUCCESS(status)) return;			// Print Error Code

	// Close Algorithm Provider
	status = BCryptCloseAlgorithmProvider(
			 algHandle,		// Algorithm Handle 
			 0);			// Flags 

	printf("\n\nRandom 16-byte: ");
	for (int i = 0; i < 16; i++) {
		printf("%02X ", random[i]);
	}

	return 0;
}




