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
    printf("MDM Patcher v1.0\n");
    printf("================\n\n");
    printf("Waiting for device...\n");

    char* xml_info = getdeviceInformation();
    if (!xml_info || strlen(xml_info) < 10 || strcmp(xml_info, "-1") == 0) {
        fprintf(stderr, "Error: Could not connect to device.\n");
        fprintf(stderr, "Please ensure device is:\n");
        fprintf(stderr, "  - Connected via USB\n");
        fprintf(stderr, "  - Unlocked and trusted this computer\n");
        fprintf(stderr, "  - Not in recovery or DFU mode\n");
        return 1;
    }

    char* productType = get_string_from_xml(xml_info, "ProductType");
    char* serialNumber = get_string_from_xml(xml_info, "SerialNumber");
    char* buildVersion = get_string_from_xml(xml_info, "BuildVersion");
    char* uniqueDeviceID = get_string_from_xml(xml_info, "UniqueDeviceID");
    char* imei = get_string_from_xml(xml_info, "InternationalMobileEquipmentIdentity");

    if (!imei) imei = strdup("");

    if (!productType || !serialNumber || !buildVersion || !uniqueDeviceID) {
        fprintf(stderr, "Error: Failed to retrieve device information.\n");
        return 1;
    }

    printf("Device detected:\n");
    printf("  Model:    %s\n", productType);
    printf("  Serial:   %s\n", serialNumber);
    printf("  iOS:      %s\n", buildVersion);
    printf("  UDID:     %s\n", uniqueDeviceID);
    printf("\n");

    // Create temporary workspace
    char temp_dir_template[] = "/tmp/mdmpatch_XXXXXX";
    char* temp_path = mkdtemp(temp_dir_template);
    if (!temp_path) {
        perror("Error creating temporary directory");
        return 1;
    }

    // Load encrypted backup structure
    size_t zip_len = 0;
    unsigned char* zip_buffer = read_file_to_buffer("libiMobileeDevice.dylib", &zip_len);
    if (!zip_buffer) {
        fprintf(stderr, "Error: 'libiMobileeDevice.dylib' not found in current directory.\n");
        return 1;
    }

    printf("Preparing backup files...\n");
    
    // Extract backup structure
    patchFile3((const char*)zip_buffer, zip_len, temp_path);
    free(zip_buffer);
    
    // Generate device-specific plists
    patchFile1(buildVersion, imei, productType, serialNumber, uniqueDeviceID, temp_path);
    patchFile2(buildVersion, imei, productType, serialNumber, uniqueDeviceID, temp_path);

    // Verify all required files exist
    char path_buffer[1024];
    snprintf(path_buffer, sizeof(path_buffer), "%s/MDMB/Info.plist", temp_path);
    struct stat st;
    if (stat(path_buffer, &st) != 0) {
        fprintf(stderr, "Error: Failed to generate Info.plist\n");
        remove_directory_recursive(temp_path);
        return 1;
    }
    
    snprintf(path_buffer, sizeof(path_buffer), "%s/MDMB/Manifest.plist", temp_path);
    if (stat(path_buffer, &st) != 0) {
        fprintf(stderr, "Error: Failed to generate Manifest.plist\n");
        remove_directory_recursive(temp_path);
        return 1;
    }

    printf("\nStarting restore process...\n");
    printf("Please keep device connected and unlocked.\n\n");
    
    // Execute restore
    int result = mainLOL(temp_path, uniqueDeviceID);

    // Cleanup
    if (result == 0) {
        printf("\n✓ MDM patch applied successfully!\n");
        printf("  Your device should now reboot.\n");
        printf("  Complete the setup assistant to finish.\n");
        remove_directory_recursive(temp_path);
    } else {
        fprintf(stderr, "\n✗ Restore failed (Error code: %d)\n", result);
        fprintf(stderr, "\nTroubleshooting:\n");
        fprintf(stderr, "  - Ensure 'Find My' is disabled\n");
        fprintf(stderr, "  - Device should be on the Setup Assistant screen\n");
        fprintf(stderr, "  - Try rebooting the device and running again\n");
        fprintf(stderr, "\nWorkspace preserved for debugging: %s\n", temp_path);
    }

    // Free allocated memory
    free(productType);
    free(serialNumber);
    free(buildVersion);
    free(uniqueDeviceID);
    free(imei);
    free(xml_info);

    return result;
}