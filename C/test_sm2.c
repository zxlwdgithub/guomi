#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sm2_cipher_error_codes.h"
#include "sm2_encrypt_and_decrypt.h"

/*********************************************************/
int test_sm2_encrypt_and_decrypt(void)
{
	int error_code;
	unsigned char msg[] = {"hello world"};
	int msg_len = (int)(strlen((char *)msg));

	unsigned char c1[65], c3[32];
	unsigned char *c2, *plaintext;
	int i;

	unsigned char pub_key[] = {0x04, 0xab, 0x64, 0x5a, 0xa3, 0xec, 0xac, 0x78, 0x45,
                              0xa5, 0xfc, 0xf6, 0xd6, 0x89, 0x53, 0xea, 0x61,
                              0x3b, 0x2d, 0x58, 0x6e, 0x2c, 0xdd, 0xd7, 0x02,
                              0x6e, 0xf9, 0xac, 0x87, 0xd2, 0x99, 0x6e, 0x10,
                              0xf1, 0xc6, 0x4c, 0x9d, 0xf2, 0x8e, 0xa6, 0x04,
                              0x07, 0xfb, 0x7f, 0x18, 0x75, 0xa9, 0xfc, 0xf7,
                              0xa3, 0x6f, 0x2a, 0xf3, 0xb0, 0x8f, 0xa5, 0x32,
                              0x96, 0xc2, 0x89, 0x4c, 0x47, 0x86, 0xa5, 0x74};
	unsigned char pri_key[32] = {0x2c, 0x4b, 0x96, 0x00, 0x22, 0x46, 0x12, 0xef,
                                0xfa, 0x24, 0x61, 0xc5, 0xd3, 0x7b, 0xca, 0x68,
                                0xdb, 0xa8, 0x3f, 0x25, 0x6a, 0x4b, 0x88, 0x30,
                                0x74, 0x2f, 0xce, 0x0c, 0xca, 0x8a, 0x91, 0x15};

	printf("Private key:\n");
	for (i = 0; i < sizeof(pri_key); i++)
	{
		printf("0x%x  ", pri_key[i]);
	}
	printf("\n\n");
	printf("Public key:\n");
	for (i = 0; i < sizeof(pub_key); i++)
	{
		printf("0x%x  ", pub_key[i]);
	}
	printf("\n\n");

	printf("/*********************************************************/\n");
	if ( !(c2 = (unsigned char *)malloc(msg_len)) )
	{
		printf("Memory allocation failed!\n");
		return ALLOCATION_MEMORY_FAIL;
	}
	if ( error_code = sm2_encrypt(msg, msg_len,
						pub_key,
						c1,
						c3,
						c2) )
	{
		printf("Create SM2 ciphertext failed!\n");
		free(c2);
		return error_code;
	}

	printf("Create SM2 ciphertext succeeded!\n");
	printf("SM2 ciphertext:\n\n");
	printf("C1 component:\n");
	for (i = 0; i < sizeof(c1); i++)
	{
		printf("0x%x  ", c1[i]);
	}
	printf("\n\n");
	printf("C3 component:\n");
	for (i = 0; i < sizeof(c3); i++)
	{
		printf("0x%x  ", c3[i]);
	}
	printf("\n\n");
	printf("Message: %s\n", msg);
	printf("The length of message is %d bytes.\n", msg_len);
	printf("The length of C2 component is %d bytes.\n", msg_len);
	printf("C2 component:\n");
	for (i = 0; i < msg_len; i++)
	{
		printf("0x%x  ", c2[i]);
	}
	printf("\n\n");

	if ( !(plaintext = (unsigned char *)malloc(msg_len)) )
	{
		printf("Memory allocation failed!\n");
		return ALLOCATION_MEMORY_FAIL;
	}

	if ( error_code = sm2_decrypt(c1, c3, c2,
				msg_len,
				pri_key,
				plaintext) )
	{
		free(plaintext);
		free(c2);
		printf("Decrypt SM2 ciphertext failed!\n");
		return error_code;
	}
	if ( memcmp(plaintext, msg, msg_len) )
	{
		printf("Decrypted plaintext is different from the input message!\n");
		return SM2_DECRYPT_FAIL;
	}
	printf("Input message:\n");
	for (i = 0; i < msg_len; i++)
	{
		printf("0x%x  ", msg[i]);
	}
	printf("\n");
	printf("Decrypted message:\n");
	for (i = 0; i < msg_len; i++)
	{
		printf("0x%x  ", plaintext[i]);
	}
	printf("\n");
	printf("Decrypt SM2 ciphertext succeeded!\n");

	free(plaintext);
	free(c2);
	return 0;
}

/*********************************************************/
int main(void)
{
	int error_code;

	printf("\n/*********************************************************/\n");
	if ( error_code = test_sm2_encrypt_and_decrypt() )
	{
		printf("Test encrypt data and decrypt ciphertext failed!\n");
		return error_code;
	}
	else
	{
		printf("Test encrypt data and decrypt ciphertext succeeded!\n");
	}

#if defined(_WIN32) || defined(_WIN64)
  system("pause");
#endif
	return 0;
}