/*
 * License Key Generator for SecureScan Pro
 * For organizational deployment and compliance
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <wincrypt.h>

void generate_license_key(const char* org_name) {
    printf("=== SecureScan Pro License Generator ===\n");
    printf("Organization: %s\n", org_name);
    
    char expected[64];
    snprintf(expected, sizeof(expected), "PROSEC_%s_2025", org_name);
    
    HCRYPTPROV hCryptProv;
    HCRYPTHASH hHash;
    DWORD hash_len = 32;
    BYTE hash[32];
    
    if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) {
            CryptHashData(hHash, (BYTE*)expected, strlen(expected), 0);
            CryptGetHashParam(hHash, HP_HASHVAL, hash, &hash_len, 0);
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hCryptProv, 0);
    }
    
    // Convert hash to hex string
    char hash_str[65] = {0};
    for (int i = 0; i < 32; i++) {
        sprintf(hash_str + i*2, "%02x", hash[i]);
    }
    
    printf("License Key: %s\n", hash_str);
    printf("\nDeployment Instructions:\n");
    printf("1. Copy SecureScan-CLI.exe and SecureScan-Pro.exe to USB drive\n");
    printf("2. Run on target systems - no installation required\n");
    printf("3. Enter organization name and license key when prompted\n");
    printf("4. Tool runs in ghost mode by default (no file artifacts)\n");
    printf("5. Use --no-ghost flag only when reports are specifically needed\n");
    printf("\nCompliance Notes:\n");
    printf("- All scans are logged with organization identity\n");
    printf("- Ghost mode ensures no traces left on target systems\n");
    printf("- Automatic cleanup removes any temporary files\n");
    printf("- Professional licensing ensures accountability\n");
    printf("=======================================\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <organization_name>\n", argv[0]);
        printf("Example: %s \"Acme Security Corp\"\n", argv[0]);
        return 1;
    }
    
    generate_license_key(argv[1]);
    return 0;
}
