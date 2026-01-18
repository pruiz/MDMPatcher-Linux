#ifndef PATCH_LOGIC_H
#define PATCH_LOGIC_H

#include <stddef.h>

/**
 * @brief Replicates Swift's Data.swapAt logic for obfuscation.
 */
void apply_byte_swaps(unsigned char* data, size_t len);

/**
 * @brief Derives the decryption password from the Swift math expression.
 * @return A heap-allocated string. Caller must free().
 */
char* get_patch_password();

/**
 * @brief Decrypts RNCryptor v3 formatted data.
 * @return 0 on success, -1 on failure.
 */
int decrypt_data(unsigned char* input, size_t input_len, const char* password, 
                 unsigned char** output, size_t* out_len);

/**
 * @brief Patches the Info.plist with device-specific metadata.
 */
void patchFile1(const char* build, const char* imei, const char* type, 
                const char* sn, const char* udid, const char* path);

/**
 * @brief Patches the Manifest.plist (Logic identical to patchFile1 but different output).
 */
void patchFile2(const char* build, const char* imei, const char* type, 
                const char* sn, const char* udid, const char* path);

/**
 * @brief Decrypts and extracts the libiMobileeDevice dylib buffer to disk.
 */
void patchFile3(const char* zip_buffer, size_t len, const char* target_path);

/**
 * @brief Utility for string substitution within the XML/Plist content.
 */
char* str_replace(const char* orig, const char* rep, const char* with);

#endif // PATCH_LOGIC_H