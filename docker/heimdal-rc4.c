/*
 * A reference partner for `rc4-hmac`, built against Heimdal's libkrb5.
 *
 * The point is not to test Heimdal: it is to have a second implementation say, in octets, what the
 * envelope of enctype 23 looks like — because RFC 4757's text leaves the layout ambiguous enough that
 * a plausible reading puts the tag at the wrong end of the buffer.
 *
 * Modes:
 *   s2k <password-hex> <salt-hex>                 -> the key, hex
 *   encrypt <key-hex> <usage> <plaintext-hex>     -> the ciphertext, hex
 *   decrypt <key-hex> <usage> <ciphertext-hex>    -> the plaintext, hex, or "err: <message>"
 *
 * `encrypt` uses Heimdal's own confounder, so its output is not reproducible; that is what makes it
 * useful for checking our *decryption*. The other direction is checked by handing this program a
 * ciphertext we produced with a fixed confounder and reading back the plaintext.
 *
 * Build: see scripts/heimdal-rc4-vectors.sh.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <krb5.h>

static void die(krb5_context ctx, krb5_error_code ret, const char *what)
{
    const char *msg = ctx ? krb5_get_error_message(ctx, ret) : NULL;
    fprintf(stderr, "%s: %s\n", what, msg ? msg : strerror(ret));
    if (ctx && msg)
        krb5_free_error_message(ctx, msg);
    exit(2);
}

static void unhex(const char *hex, unsigned char **out, size_t *len)
{
    size_t n = strlen(hex) / 2, i;
    unsigned char *p = calloc(n ? n : 1, 1);

    if (p == NULL)
        exit(2);
    for (i = 0; i < n; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1)
            exit(2);
        p[i] = (unsigned char)byte;
    }
    *out = p;
    *len = n;
}

static void print_hex(const void *data, size_t len)
{
    const unsigned char *p = data;
    size_t i;

    for (i = 0; i < len; i++)
        printf("%02x", p[i]);
    printf("\n");
}

int main(int argc, char **argv)
{
    krb5_context ctx = NULL;
    krb5_error_code ret;

    if (argc < 2) {
        fprintf(stderr, "usage: %s s2k|encrypt|decrypt ...\n", argv[0]);
        return 2;
    }

    ret = krb5_init_context(&ctx);
    if (ret)
        die(NULL, ret, "krb5_init_context");

    if (strcmp(argv[1], "s2k") == 0 && argc == 4) {
        unsigned char *password = NULL, *salt_bytes = NULL;
        size_t password_len = 0, salt_len = 0;
        krb5_salt salt;
        krb5_keyblock key;

        unhex(argv[2], &password, &password_len);
        unhex(argv[3], &salt_bytes, &salt_len);
        /* The password is text to this API, so it is passed through unchanged: the UTF-16LE step is
         * Heimdal's, and the fixture is about what Heimdal produces. */
        salt.salttype = KRB5_PW_SALT;
        salt.saltvalue.data = (char *)salt_bytes;
        salt.saltvalue.length = (unsigned)salt_len;
        memset(&key, 0, sizeof(key));
        ret = krb5_string_to_key_salt(ctx, ETYPE_ARCFOUR_HMAC_MD5, (const char *)password, salt, &key);
        if (ret)
            die(ctx, ret, "krb5_string_to_key_salt");
        print_hex(key.keyvalue.data, key.keyvalue.length);
        krb5_free_keyblock_contents(ctx, &key);
    } else if ((strcmp(argv[1], "encrypt") == 0 || strcmp(argv[1], "decrypt") == 0) && argc == 5) {
        unsigned char *key_bytes = NULL, *data = NULL;
        size_t key_len = 0, data_len = 0;
        krb5_keyblock key;
        krb5_data plain, cipher, out;
        krb5_crypto crypto = NULL;

        unhex(argv[2], &key_bytes, &key_len);
        unhex(argv[4], &data, &data_len);
        if (key_len != 16) {
            fprintf(stderr, "a rc4-hmac key is 16 octets, got %zu\n", key_len);
            return 2;
        }

        memset(&key, 0, sizeof(key));
        key.keytype = ETYPE_ARCFOUR_HMAC_MD5;
        key.keyvalue.data = key_bytes;
        key.keyvalue.length = (unsigned)key_len;

        ret = krb5_crypto_init(ctx, &key, 0, &crypto);
        if (ret)
            die(ctx, ret, "krb5_crypto_init");

        plain.data = (char *)data;
        plain.length = (unsigned)data_len;
        memset(&cipher, 0, sizeof(cipher));
        memset(&out, 0, sizeof(out));

        if (strcmp(argv[1], "encrypt") == 0) {
            ret = krb5_encrypt(ctx, crypto, (unsigned)atoi(argv[3]), plain.data, plain.length, &cipher);
            if (ret)
                die(ctx, ret, "krb5_encrypt");
            print_hex(cipher.data, cipher.length);
            krb5_data_free(&cipher);
        } else {
            ret = krb5_decrypt(ctx, crypto, (unsigned)atoi(argv[3]), plain.data, plain.length, &out);
            if (ret) {
                const char *msg = krb5_get_error_message(ctx, ret);
                printf("err: %s\n", msg ? msg : "?");
                krb5_free_error_message(ctx, msg);
            } else {
                print_hex(out.data, out.length);
                krb5_data_free(&out);
            }
        }
        krb5_crypto_destroy(ctx, crypto);
        krb5_free_keyblock_contents(ctx, &key);
    } else {
        fprintf(stderr, "bad arguments\n");
        return 2;
    }

    krb5_free_context(ctx);
    return 0;
}
