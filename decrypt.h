#ifndef _DECRYPT_H_
#define _DECRYPT_H_

/* Base64Decode.c */
int Base64Decode(char *, unsigned char **, size_t *);

/* decrypt.c */
unsigned char *decrypt(char *);

#endif /* !_DECRYPT_H_ */
