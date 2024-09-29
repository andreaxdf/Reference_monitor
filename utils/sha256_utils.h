#ifndef SHA256_UTILS_H
#define SHA256_UTILS_H

#include <crypto/hash.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/types.h>

#define SHA256_DIGEST_SIZE 256 / 8

int compute_crypto_digest(const unsigned char *data, unsigned int datalen,
                          unsigned char *digest);

int verify_password(const unsigned char *password, unsigned int passlen,
                    const unsigned char *expected_hash);

#endif
