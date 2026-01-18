#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <zip.h>
#include <sys/stat.h>
#include <errno.h>
#include "patch_logic.h"

// --- Helper: Recursive Directory Creation ---
int mkdir_p(const char *path) {
    char temp[1024];
    char *p = NULL;
    size_t len;
    snprintf(temp, sizeof(temp), "%s", path);
    len = strlen(temp);
    if (temp[len - 1] == '/') temp[len - 1] = 0;
    for (p = temp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            if (mkdir(temp, 0755) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(temp, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

void ensure_parent_dir_exists(const char* filepath) {
    char* parent = strdup(filepath);
    char* slash = strrchr(parent, '/');
    if (slash) {
        *slash = '\0';
        mkdir_p(parent);
    }
    free(parent);
}

// --- Helper: String replacement ---
char* str_replace(const char* orig, const char* rep, const char* with) {
    char* result;
    char* ins;
    char* tmp;
    int len_rep;
    int len_with;
    int len_front;
    int count;
    if (!orig || !rep) return NULL;
    len_rep = strlen(rep);
    if (len_rep == 0) return NULL;
    if (!with) with = "";
    len_with = strlen(with);
    ins = (char*)orig;
    for (count = 0; (tmp = strstr(ins, rep)); ++count) ins = tmp + len_rep;
    tmp = result = malloc(strlen(orig) + (len_with - len_rep) * count + 1);
    if (!result) return NULL;
    while (count--) {
        ins = strstr(orig, rep);
        len_front = ins - orig;
        tmp = strncpy(tmp, orig, len_front) + len_front;
        tmp = strcpy(tmp, with) + len_with;
        orig += len_front + len_rep;
    }
    strcpy(tmp, orig);
    return result;
}

void apply_byte_swaps(unsigned char* data, size_t len) {
    if (len < 346) return;
    unsigned char tmp;
    #define SWAP(a, b) tmp = data[a]; data[a] = data[b]; data[b] = tmp;
    SWAP(3, 5); SWAP(8, 17); SWAP(128, 345);
    SWAP(15, 65); SWAP(33, 133); SWAP(16, 64);
}

// --- Core Logic: RNCryptor v3 Decryption with HMAC Verification ---
int try_decrypt_with_hmac(unsigned char* input, size_t input_len, const char* password, 
                          unsigned char** output, size_t* out_len) {
    if (input_len < 66) return -1;
    if (input[0] != 3) return -1;
    
    unsigned char* enc_salt = input + 2;
    unsigned char* hmac_salt = input + 10;
    unsigned char* iv = input + 18;
    unsigned char* ciphertext = input + 34;
    size_t cipher_len = input_len - 66;
    unsigned char* stored_hmac = input + input_len - 32;
    
    // Derive keys using PBKDF2-HMAC-SHA1 with 10,000 iterations (RNCryptor v3 spec)
    unsigned char enc_key[32];
    unsigned char hmac_key[32];
    
    PKCS5_PBKDF2_HMAC_SHA1(password, strlen(password), enc_salt, 8, 10000, 32, enc_key);
    PKCS5_PBKDF2_HMAC_SHA1(password, strlen(password), hmac_salt, 8, 10000, 32, hmac_key);
    
    // Verify HMAC (password check)
    unsigned char computed_hmac[32];
    unsigned int hmac_len;
    HMAC(EVP_sha256(), hmac_key, 32, input, input_len - 32, computed_hmac, &hmac_len);
    
    if (memcmp(computed_hmac, stored_hmac, 32) != 0) {
        return -1; // Wrong password
    }
    
    // Decrypt using AES-256-CBC
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, enc_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    *output = malloc(cipher_len + 32);
    int len, final_len;
    
    if (EVP_DecryptUpdate(ctx, *output, &len, ciphertext, (int)cipher_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*output);
        *output = NULL;
        return -1;
    }
    
    if (EVP_DecryptFinal_ex(ctx, *output + len, &final_len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        free(*output);
        *output = NULL;
        return -1;
    }
    
    *out_len = len + final_len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

// Master decryption function using the correct password
int smart_decrypt(unsigned char* input, size_t len, unsigned char** output, size_t* out_len) {
    // Password derived from Swift's Double calculation and string interpolation
    // This exact byte sequence is required for decryption
    unsigned char password_bytes[] = {
        0x72, 0x65, 0x70, 0x6B, 0x77, 0x6F, 0x74, 0x6B, 0x67, 0x70, 0x65, 0x72, 0x67, 0x70, 0x65, 0x6F,
        0x6B, 0x72, 0x67, 0x6F, 0x6B, 0x67, 0x72, 0x6F, 0x65, 0x2D, 0x34, 0x2E, 0x30, 0x34, 0x31, 0x38,
        0x33, 0x36, 0x34, 0x32, 0x34, 0x38, 0x35, 0x34, 0x36, 0x39, 0x36, 0x35, 0x65, 0x2B, 0x32, 0x36,
        0x66, 0x64, 0x6C, 0x67, 0x6B, 0x64, 0x6C, 0x67, 0x66, 0x6B, 0x6C, 0x73, 0x64, 0xC3, 0xB6, 0x66,
        0x64, 0x67, 0x73, 0x6A, 0x2D, 0x34, 0x2E, 0x30, 0x34, 0x31, 0x38, 0x33, 0x36, 0x34, 0x32, 0x34,
        0x38, 0x35, 0x34, 0x36, 0x39, 0x36, 0x35, 0x65, 0x2B, 0x32, 0x36, 0x67, 0x66, 0x64, 0x61, 0x64,
        0x73, 0x32, 0x33, 0x6A, 0x69, 0x34, 0x6A, 0x67, 0x69, 0x33, 0x76, 0x72, 0x65, 0x77, 0xC3, 0xB6,
        0x00
    };
    
    return try_decrypt_with_hmac(input, len, (char*)password_bytes, output, out_len);
}

// --- Patch Functions ---

void patchFile1(const char* build, const char* imei, const char* type, const char* sn, const char* udid, const char* path) {
    printf("[Patch 1] Processing Info.plist template...\n");
    FILE* f = fopen("extension1.pdf", "rb");
    if (!f) {
        printf("[ERROR] extension1.pdf not found\n");
        return;
    }
    
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char* buffer = malloc(size);
    fread(buffer, 1, size, f);
    fclose(f);

    apply_byte_swaps(buffer, size);

    unsigned char* decrypted = NULL;
    size_t dec_len = 0;

    if (smart_decrypt(buffer, size, &decrypted, &dec_len) == 0) {
        apply_byte_swaps(decrypted, dec_len);

        char* str = malloc(dec_len + 1);
        memcpy(str, decrypted, dec_len);
        str[dec_len] = '\0';

        // Apply device-specific replacements
        char* working = str_replace(str, "18C66", build);
        
        char* next;
        if (strlen(imei) == 0) {
            char imei_block[100] = "\t<key>IMEI</key>\n\t<string>357145413514797</string>\n";
            next = str_replace(working, imei_block, "");
        } else {
            next = str_replace(working, "357145413514797", imei);
        }
        free(working);
        working = next;

        char* s3 = str_replace(working, "iPhone12,8", type);
        free(working);
        char* s4 = str_replace(s3, "F17F4MLSPLK2", sn);
        free(s3);
        char* final_str = str_replace(s4, "00008030-001854E42E06402E", udid);
        free(s4);

        char out_path[1024];
        sprintf(out_path, "%s/MDMB/Info.plist", path);
        ensure_parent_dir_exists(out_path);
        
        FILE* out_f = fopen(out_path, "wb");
        if (out_f) {
            fwrite(final_str, 1, strlen(final_str), out_f);
            fclose(out_f);
            printf("[Patch 1] Info.plist created successfully\n");
        } else {
            printf("[ERROR] Failed to write Info.plist: %s\n", strerror(errno));
        }
        
        free(final_str);
        free(str);
        free(decrypted);
    } else {
        printf("[ERROR] Failed to decrypt extension1.pdf\n");
    }
    free(buffer);
}

void patchFile2(const char* build, const char* imei, const char* type, const char* sn, const char* udid, const char* path) {
    printf("[Patch 2] Processing Manifest.plist template...\n");
    FILE* f = fopen("extension2.pdf", "rb");
    if (!f) {
        printf("[ERROR] extension2.pdf not found\n");
        return;
    }
    
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char* buffer = malloc(size);
    fread(buffer, 1, size, f);
    fclose(f);

    apply_byte_swaps(buffer, size);

    unsigned char* decrypted = NULL;
    size_t dec_len = 0;

    if (smart_decrypt(buffer, size, &decrypted, &dec_len) == 0) {
        apply_byte_swaps(decrypted, dec_len);

        char* str = malloc(dec_len + 1);
        memcpy(str, decrypted, dec_len);
        str[dec_len] = '\0';

        // Apply device-specific replacements
        char* s1 = str_replace(str, "18C66", build);
        char* s2 = str_replace(s1, "iPhone12,8", type);
        free(s1);
        char* s3 = str_replace(s2, "F17F4MLSPLK2", sn);
        free(s2);
        char* final_str = str_replace(s3, "00008030-001854E42E06402E", udid);
        free(s3);

        char out_path[1024];
        sprintf(out_path, "%s/MDMB/Manifest.plist", path);
        ensure_parent_dir_exists(out_path);

        FILE* out_f = fopen(out_path, "wb");
        if (out_f) {
            fwrite(final_str, 1, strlen(final_str), out_f);
            fclose(out_f);
            printf("[Patch 2] Manifest.plist created successfully\n");
        } else {
            printf("[ERROR] Failed to write Manifest.plist: %s\n", strerror(errno));
        }
        
        free(final_str);
        free(str);
        free(decrypted);
    } else {
        printf("[ERROR] Failed to decrypt extension2.pdf\n");
    }
    free(buffer);
}

void patchFile3(const char* zip_buffer, size_t len, const char* target_path) {
    printf("[Patch 3] Extracting backup structure...\n");
    unsigned char* data_copy = malloc(len);
    memcpy(data_copy, zip_buffer, len);
    apply_byte_swaps(data_copy, len);

    unsigned char* decrypted = NULL;
    size_t dec_len = 0;

    if (smart_decrypt(data_copy, len, &decrypted, &dec_len) == 0) {
        apply_byte_swaps(decrypted, dec_len);
        
        zip_error_t zerr;
        zip_source_t *src = zip_source_buffer_create(decrypted, dec_len, 0, &zerr);
        zip_t *za = zip_open_from_source(src, ZIP_RDONLY, &zerr);
        
        if (za) {
            zip_int64_t num_entries = zip_get_num_entries(za, 0);
            printf("[Patch 3] Extracting %lld files...\n", (long long)num_entries);
            
            for (zip_int64_t i = 0; i < num_entries; i++) {
                const char* name = zip_get_name(za, i, 0);
                char full_path[1024];
                sprintf(full_path, "%s/%s", target_path, name);
                ensure_parent_dir_exists(full_path);

                if (name[strlen(name)-1] == '/') {
                    mkdir_p(full_path);
                    continue;
                }

                zip_file_t *zf = zip_fopen_index(za, i, 0);
                if (zf) {
                    FILE* out = fopen(full_path, "wb");
                    if (out) {
                        char buf[8192];
                        zip_int64_t n;
                        while ((n = zip_fread(zf, buf, sizeof(buf))) > 0) {
                            fwrite(buf, 1, n, out);
                        }
                        fclose(out);
                    }
                    zip_fclose(zf);
                }
            }
            zip_close(za);
            printf("[Patch 3] Extraction complete\n");
        } else {
            printf("[ERROR] Failed to open ZIP archive\n");
        }
        free(decrypted);
    } else {
        printf("[ERROR] Failed to decrypt backup structure\n");
    }
    free(data_copy);
}