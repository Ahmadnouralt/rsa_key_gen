#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

int generate_rsa_keys(const char *pub_path, const char *priv_path) {
    int ret = 0;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    FILE *pub_file = NULL;
    FILE *priv_file = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        ret = -1;
        goto cleanup;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        ERR_print_errors_fp(stderr);
        ret = -1;
        goto cleanup;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        ERR_print_errors_fp(stderr);
        ret = -1;
        goto cleanup;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        ERR_print_errors_fp(stderr);
        ret = -1;
        goto cleanup;
    }

    pub_file = fopen(pub_path, "wb");
    priv_file = fopen(priv_path, "wb");
    if (!pub_file || !priv_file) {
        perror("file");
        ret = -1;
        goto cleanup;
    }

    if (!PEM_write_PUBKEY(pub_file, pkey)) {
        ERR_print_errors_fp(stderr);
        ret = -1;
        goto cleanup;
    }

    if (!PEM_write_PrivateKey(priv_file, pkey, NULL, NULL, 0, NULL, NULL)) {
        ERR_print_errors_fp(stderr);
        ret = -1;
        goto cleanup;
    }

cleanup:
    if (pub_file) fclose(pub_file);
    if (priv_file) fclose(priv_file);
    if (pkey) EVP_PKEY_free(pkey);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    return ret;
}

int main(int argc, char *argv[]) {

    printf("\n=====================================\n");
    printf("        RSA Key Generator v1.0\n");
    printf("=====================================\n");

    if (argc < 3) {
        printf("\nUsage:\n");
        printf("  %s <public_key.pem> <private_key.pem>\n", argv[0]);
        printf("Example:\n");
        printf("  %s pub.pem priv.pem\n\n", argv[0]);
        return 1;
    }

    const char *pub_path = argv[1];
    const char *priv_path = argv[2];

    printf("\nGenerating RSA 2048-bit keys...\n");

    int result = generate_rsa_keys(pub_path, priv_path);

    if (result == 0) {
        printf("\n✔ Keys generated successfully!\n");
        printf("Public key saved to : %s\n", pub_path);
        printf("Private key saved to: %s\n", priv_path);
    } else {
        printf("\n✘ Key generation failed.\n");
    }

    printf("\n=====================================\n");
    printf("              Done\n");
    printf("=====================================\n\n");
    printf("\nPress Enter to exit...");
    system("pause");


    return result;
}
