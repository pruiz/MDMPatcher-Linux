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

// --- Core Logic: Password & Decryption ---

// Helper to generate password from 'i' string
char* generate_pass_from_i(const char* i_str) {
    // Base: "qepkwotkgpeqgpeokqgokgqoe%sfdlgkdlgfklsdöfdgsj%sgfdads23ji4jgi3vqewö"
    // We pre-replaced 'q' with 'r' in the format string below to match Swift's .replacingOccurrences(of: "q", with: "r")
    char* base = "repkwotkgperperokrgokrgoe%sfdlgkdlgfklsdöfdgsj%sgfdads23ji4jgi3vqewö";
    char* pass = malloc(1024);
    if (pass) sprintf(pass, base, i_str, i_str);
    return pass;
}



// Complete RNCryptor v3 decryption with HMAC verification
int try_decrypt(unsigned char* input, size_t input_len, const char* password, 
                          unsigned char** output, size_t* out_len) {
    if (input_len < 66) {
        printf("[DEBUG] File too small: %zu bytes (need at least 66)\n", input_len);
        return -1;
    }
    
    if (input[0] != 3) {
        printf("[DEBUG] Wrong version: %d (expected 3)\n", input[0]);
        return -1;
    }
    
    unsigned char options = input[1];
    unsigned char* enc_salt = input + 2;
    unsigned char* hmac_salt = input + 10;
    unsigned char* iv = input + 18;
    unsigned char* ciphertext = input + 34;
    size_t cipher_len = input_len - 66;
    unsigned char* stored_hmac = input + input_len - 32;
    
    // Derive keys
    unsigned char enc_key[32];
    unsigned char hmac_key[32];
    
    PKCS5_PBKDF2_HMAC_SHA1(password, strlen(password), enc_salt, 8, 10000, 32, enc_key);
    PKCS5_PBKDF2_HMAC_SHA1(password, strlen(password), hmac_salt, 8, 10000, 32, hmac_key);
    
    // Verify HMAC (RNCryptor v3 HMACs the header + ciphertext, not including the HMAC itself)
    unsigned char computed_hmac[32];
    unsigned int hmac_len;
    
    HMAC(EVP_sha256(), hmac_key, 32, input, input_len - 32, computed_hmac, &hmac_len);
    
    if (memcmp(computed_hmac, stored_hmac, 32) != 0) {
        printf("[DEBUG] HMAC verification failed - wrong password\n");
        printf("[DEBUG] Expected HMAC: ");
        for (int i = 0; i < 32; i++) printf("%02X", stored_hmac[i]);
        printf("\n[DEBUG] Computed HMAC: ");
        for (int i = 0; i < 32; i++) printf("%02X", computed_hmac[i]);
        printf("\n");
        return -1;
    }
    
    printf("[DEBUG] ✓ HMAC verified! Password is correct.\n");
    
    // Decrypt
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
        printf("[DEBUG] Padding error during final decrypt\n");
        EVP_CIPHER_CTX_free(ctx);
        free(*output);
        *output = NULL;
        return -1;
    }
    
    *out_len = len + final_len;
    EVP_CIPHER_CTX_free(ctx);
    
    printf("[DEBUG] ✓ Decryption successful! Plaintext size: %zu bytes\n", *out_len);
    return 0;
}

// Replace your try_decrypt function with this one

// Tries to decrypt using a specific password
int try_decrypt_old(unsigned char* input, size_t input_len, const char* password, unsigned char** output, size_t* out_len) {
    // RNCryptor v3: Version(1) + Options(1) + EncSalt(8) + HMACSalt(8) + IV(16) + CipherText(...) + HMAC(32)
    // Total Header size = 1 + 1 + 8 + 8 + 16 = 34 bytes
    if (input_len < 34 + 32) return -1; 

    // Validate Version 3
    if (input[0] != 3) {
        printf("[DEBUG] Invalid RNCryptor version: %d (Expected 3)\n", input[0]);
        return -1;
    }

    unsigned char* enc_salt = input + 2;   // Offset 2, len 8
    // unsigned char* hmac_salt = input + 10; // Offset 10, len 8 (Unused for AES extraction)
    unsigned char* iv        = input + 18; // Offset 18, len 16
    unsigned char* ciphertext = input + 34; // Offset 34
    size_t cipher_len = input_len - 34 - 32; // Total - Header - HMAC Footer

    unsigned char key[32];
    // RNCryptor uses PBKDF2-HMAC-SHA1 with 10,000 iterations for the AES key
    PKCS5_PBKDF2_HMAC_SHA1(password, strlen(password), enc_salt, 8, 10000, 32, key);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    
    // RNCryptor uses AES-256-CBC
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    *output = malloc(cipher_len + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len, final_len;

    if (EVP_DecryptUpdate(ctx, *output, &len, ciphertext, (int)cipher_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*output);
        *output = NULL;
        return -1;
    }
    
    // Check padding (This is effectively our password verification)
    if (EVP_DecryptFinal_ex(ctx, *output + len, &final_len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        free(*output);
        *output = NULL;
        return -1; // Wrong password or corrupted data
    }

    *out_len = len + final_len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

// Replace the smart_decrypt function in patch_logic.c with this version

// Replace the smart_decrypt function with this version
// Uses the EXACT password from Swift's actual output

int smart_decrypt(unsigned char* input, size_t len, unsigned char** output, size_t* out_len) {
    printf("[DEBUG] Attempting decryption with multiple password candidates\n\n");
    
    // Candidate 1: EXACT bytes from Swift output (has 'gperg')
    unsigned char password1[] = {
        0x72, 0x65, 0x70, 0x6B, 0x77, 0x6F, 0x74, 0x6B, 0x67, 0x70, 0x65, 0x72, 0x67, 0x70, 0x65, 0x6F,
        0x6B, 0x72, 0x67, 0x6F, 0x6B, 0x67, 0x72, 0x6F, 0x65, 0x2D, 0x34, 0x2E, 0x30, 0x34, 0x31, 0x38,
        0x33, 0x36, 0x34, 0x32, 0x34, 0x38, 0x35, 0x34, 0x36, 0x39, 0x36, 0x35, 0x65, 0x2B, 0x32, 0x36,
        0x66, 0x64, 0x6C, 0x67, 0x6B, 0x64, 0x6C, 0x67, 0x66, 0x6B, 0x6C, 0x73, 0x64, 0xC3, 0xB6, 0x66,
        0x64, 0x67, 0x73, 0x6A, 0x2D, 0x34, 0x2E, 0x30, 0x34, 0x31, 0x38, 0x33, 0x36, 0x34, 0x32, 0x34,
        0x38, 0x35, 0x34, 0x36, 0x39, 0x36, 0x35, 0x65, 0x2B, 0x32, 0x36, 0x67, 0x66, 0x64, 0x61, 0x64,
        0x73, 0x32, 0x33, 0x6A, 0x69, 0x34, 0x6A, 0x67, 0x69, 0x33, 0x76, 0x72, 0x65, 0x77, 0xC3, 0xB6,
        0x00
    };
    
    // Candidate 2: What the password SHOULD be based on the replacement logic (has 'gper' not 'gperg')
    const char* i_str = "-4.0418364248546965e+26";
    char password2[256];
    snprintf(password2, sizeof(password2),
        "repkwotkgperperokrgokrgoe%sfdlgkdlgfklsd\xC3\xB6fdgsj%sgfdads23ji4jgi3vrew\xC3\xB6",
        i_str, i_str);
    
    // Try both candidates
    const char* passwords[] = {(char*)password1, password2};
    const char* names[] = {
        "Exact Swift output (with 'gperg')",
        "Logically correct (with 'gper')"
    };
    
    for (int i = 0; i < 2; i++) {
        printf("[DEBUG] Candidate %d: %s\n", i+1, names[i]);
        printf("[DEBUG]   Password: %s\n", passwords[i]);
        printf("[DEBUG]   Length: %zu\n", strlen(passwords[i]));
        
        if (try_decrypt(input, len, passwords[i], output, out_len) == 0) {
            printf("[DEBUG] ✓✓✓ SUCCESS with candidate %d! ✓✓✓\n", i+1);
            return 0;
        }
        printf("\n");
    }
    
    printf("[DEBUG] ✗ Both password candidates failed\n");
    return -1;
}

// --- Patch Functions ---

void patchFile1(const char* build, const char* imei, const char* type, const char* sn, const char* udid, const char* path) {
    printf("[Patch 1] Processing extension1.pdf...\n");
    FILE* f = fopen("extension1.pdf", "rb");
    if (!f) { printf("[Patch 1] Error: File not found.\n"); return; }
    fseek(f, 0, SEEK_END); size_t size = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char* buffer = malloc(size); fread(buffer, 1, size, f); fclose(f);

    apply_byte_swaps(buffer, size);

    unsigned char* decrypted = NULL;
    size_t dec_len = 0;

    if (smart_decrypt(buffer, size, &decrypted, &dec_len) == 0) {
        apply_byte_swaps(decrypted, dec_len);

        char* str = malloc(dec_len + 1);
        memcpy(str, decrypted, dec_len);
        str[dec_len] = '\0';

        char* working = str_replace(str, "18C66", build);
        
        char* next;
        if (strlen(imei) == 0) {
            char imei_block[100] = "\t<key>IMEI</key>\n\t<string>357145413514797</string>\n";
            next = str_replace(working, imei_block, "");
        } else {
            next = str_replace(working, "357145413514797", imei);
        }
        free(working); working = next;

        char* s3 = str_replace(working, "iPhone12,8", type); free(working);
        char* s4 = str_replace(s3, "F17F4MLSPLK2", sn); free(s3);
        char* final_str = str_replace(s4, "00008030-001854E42E06402E", udid); free(s4);

        char out_path[1024];
        sprintf(out_path, "%s/MDMB/Info.plist", path);
        ensure_parent_dir_exists(out_path);
        
        FILE* out_f = fopen(out_path, "wb");
        if (out_f) { fwrite(final_str, 1, strlen(final_str), out_f); fclose(out_f); }
        else { printf("[Patch 1] Failed to write Info.plist: %s\n", strerror(errno)); }
        
        free(final_str); free(str); free(decrypted);
    } else {
        printf("[Patch 1] Failed to decrypt.\n");
    }
    free(buffer);
}

void patchFile2(const char* build, const char* imei, const char* type, const char* sn, const char* udid, const char* path) {
    printf("[Patch 2] Processing extension2.pdf...\n");
    FILE* f = fopen("extension2.pdf", "rb");
    if (!f) { printf("[Patch 2] Error: File not found.\n"); return; }
    fseek(f, 0, SEEK_END); size_t size = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char* buffer = malloc(size); fread(buffer, 1, size, f); fclose(f);

    apply_byte_swaps(buffer, size);

    unsigned char* decrypted = NULL;
    size_t dec_len = 0;

    if (smart_decrypt(buffer, size, &decrypted, &dec_len) == 0) {
        apply_byte_swaps(decrypted, dec_len);

        char* str = malloc(dec_len + 1);
        memcpy(str, decrypted, dec_len);
        str[dec_len] = '\0';

        char* s1 = str_replace(str, "18C66", build);
        char* s2 = str_replace(s1, "iPhone12,8", type); free(s1);
        char* s3 = str_replace(s2, "F17F4MLSPLK2", sn); free(s2);
        char* final_str = str_replace(s3, "00008030-001854E42E06402E", udid); free(s3);

        char out_path[1024];
        sprintf(out_path, "%s/MDMB/Manifest.plist", path);
        ensure_parent_dir_exists(out_path);

        FILE* out_f = fopen(out_path, "wb");
        if (out_f) { fwrite(final_str, 1, strlen(final_str), out_f); fclose(out_f); }
        else { printf("[Patch 2] Failed to write Manifest.plist: %s\n", strerror(errno)); }
        
        free(final_str); free(str); free(decrypted);
    } else {
        printf("[Patch 2] Failed to decrypt.\n");
    }
    free(buffer);
}

void patchFile3(const char* zip_buffer, size_t len, const char* target_path) {
    printf("[Patch 3] Processing ZIP buffer (%zu bytes)...\n", len);
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
            printf("[Patch 3] Extracting %lld entries to %s...\n", (long long)num_entries, target_path);
            
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
                        while ((n = zip_fread(zf, buf, sizeof(buf))) > 0) fwrite(buf, 1, n, out);
                        fclose(out);
                    }
                    zip_fclose(zf);
                }
            }
            zip_close(za);
        } else {
            printf("[Patch 3] Failed to open ZIP structure: %d\n", zerr.zip_err);
        }
        free(decrypted);
    } else {
        printf("[Patch 3] Failed to decrypt.\n");
    }
    free(data_copy);
}