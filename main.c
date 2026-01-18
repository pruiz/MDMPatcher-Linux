#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <plist/plist.h>

#include "libidevicefunctions.h"
#include "idevicebackup2.h"
#include "patch_logic.h"

#define TOOL_NAME "mdm_patcher"

// Helper to check if a file exists and print size
void debug_check_file(const char* path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        printf(" [DEBUG] Found: %s (%lld bytes)\n", path, (long long)st.st_size);
    } else {
        printf(" [DEBUG] MISSING: %s (Error: %s)\n", path, strerror(errno));
    }
}

// Helper to list directory contents
void debug_list_dir(const char* path) {
    printf(" [DEBUG] Listing contents of %s:\n", path);
    DIR *d;
    struct dirent *dir;
    d = opendir(path);
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            if (dir->d_type == DT_REG) printf("  - %s\n", dir->d_name);
            else if (dir->d_type == DT_DIR) printf("  [D] %s\n", dir->d_name);
        }
        closedir(d);
    }
}

unsigned char* read_file_to_buffer(const char* filename, size_t* size) {
    FILE* f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "Error: Could not open file %s\n", filename);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    *size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    unsigned char* buffer = malloc(*size);
    if (!buffer) {
        fclose(f);
        return NULL;
    }
    
    if (fread(buffer, 1, *size, f) != *size) {
        fprintf(stderr, "Error: Could not read entire file %s\n", filename);
        free(buffer);
        fclose(f);
        return NULL;
    }
    
    fclose(f);
    return buffer;
}

char* get_string_from_xml(const char* xml, const char* key) {
    if (!xml) return NULL;
    plist_t plist = NULL;
    char* result = NULL;
    plist_from_xml(xml, strlen(xml), &plist);
    if (!plist) return NULL;
    plist_t node = plist_dict_get_item(plist, key);
    if (node && plist_get_node_type(node) == PLIST_STRING) {
        plist_get_string_val(node, &result);
    }
    plist_free(plist);
    return result; 
}

void remove_directory_recursive(const char *path) {
    char command[1024];
    snprintf(command, sizeof(command), "rm -rf \"%s\"", path);
    system(command);
}

int main(int argc, char *argv[]) {
    printf("--- MDM Patcher Debug Mode ---\n");
    printf("Waiting for device...\n");

    char* xml_info = getdeviceInformation();
    if (!xml_info || strlen(xml_info) < 10 || strcmp(xml_info, "-1") == 0) {
        fprintf(stderr, "Error: Could not connect to device. Ensure it is plugged in and 'Trusted'.\n");
        return 1;
    }

    char* productType = get_string_from_xml(xml_info, "ProductType");
    char* serialNumber = get_string_from_xml(xml_info, "SerialNumber");
    char* buildVersion = get_string_from_xml(xml_info, "BuildVersion");
    char* uniqueDeviceID = get_string_from_xml(xml_info, "UniqueDeviceID");
    char* imei = get_string_from_xml(xml_info, "InternationalMobileEquipmentIdentity");

    if (!imei) imei = strdup("");

    if (!productType || !serialNumber || !buildVersion || !uniqueDeviceID) {
        fprintf(stderr, "Error: Failed to retrieve device metadata from XML.\n");
        return 1;
    }

    printf("Target Device: %s | %s | %s\n", productType, serialNumber, buildVersion);

    char temp_dir_template[] = "/tmp/mdmpatch_XXXXXX";
    char* temp_path = mkdtemp(temp_dir_template);
    if (!temp_path) {
        perror("Error creating temporary directory");
        return 1;
    }
    printf("Workspace: %s\n", temp_path);

    size_t zip_len = 0;
    unsigned char* zip_buffer = read_file_to_buffer("libiMobileeDevice.dylib", &zip_len);
    if (!zip_buffer) {
        fprintf(stderr, "Critical Error: 'libiMobileeDevice.dylib' not found in current directory!\n");
        return 1;
    }

    printf("Executing Patch Logic...\n");
    
    // 1. Extract ZIP structure
    patchFile3((const char*)zip_buffer, zip_len, temp_path);
    free(zip_buffer);
    
    // 2. Generate Plists
    patchFile1(buildVersion, imei, productType, serialNumber, uniqueDeviceID, temp_path);
    patchFile2(buildVersion, imei, productType, serialNumber, uniqueDeviceID, temp_path);

    // DEBUG: Verify files before restore
    printf("\n--- Verifying Patch Files ---\n");
    debug_list_dir(temp_path);
    char path_buffer[1024];
    snprintf(path_buffer, sizeof(path_buffer), "%s/Info.plist", temp_path);
    debug_check_file(path_buffer);
    snprintf(path_buffer, sizeof(path_buffer), "%s/Manifest.plist", temp_path);
    debug_check_file(path_buffer);
    printf("-----------------------------\n\n");

    printf("Starting Restore process (Handshaking with MobileBackup2)...\n");
    
    // Call the engine
    int result = mainLOL(temp_path, uniqueDeviceID);

    if (result == 0) {
        printf("\n[SUCCESS] MDM Patch Applied.\n");
        printf("Cleaning up workspace...\n");
        remove_directory_recursive(temp_path);
    } else {
        printf("\n[ERROR] Restore Failed (Code: %d).\n", result);
        printf("[DEBUG] Workspace NOT deleted for inspection: %s\n", temp_path);
        printf("[DEBUG] Check if 'Find My' is OFF and device is on Setup Assistant.\n");
    }

    free(productType); free(serialNumber); free(buildVersion);
    free(uniqueDeviceID); free(imei); free(xml_info);

    return result;
}