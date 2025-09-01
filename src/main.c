#include "engine.h"
#include "secure_ops.h"
#include "security_hardening.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <direct.h>
#define MKDIR(path) _mkdir(path)
#else
#include <sys/stat.h>
#define MKDIR(path) mkdir(path, 0755)
#endif

// No longer create reports directory in ghost mode
static void ensure_reports_dir(void) {
    if (is_ghost_mode()) {
        printf("[GHOST] Operating in stealth mode - no file artifacts\n");
        return;  // Skip directory creation in ghost mode
    }
    
    // Legacy mode - create reports directory  
    FILE *f = fopen("reports/.probe","w");
    if(!f) {
        /* try create */
        MKDIR("reports");
        f = fopen("reports/.probe","w");
    }
    if(f) { fclose(f); remove("reports/.probe"); }
}

static void run_full(const char *target) {
    module_result_t *recon=NULL; size_t recon_count=0;
    if(run_recon(target, &recon, &recon_count)!=0) {
        fprintf(stderr, "[!] Recon failed\n");
        return;
    }
    module_result_t *vuln=NULL; size_t vuln_count=0;
    if(run_vuln(target, &vuln, &vuln_count)!=0) {
        fprintf(stderr, "[!] Vuln scan failed\n");
        free_results(recon, recon_count);
        return;
    }
    
    // Add AI/ML analysis
    module_result_t *ai_results=NULL; size_t ai_count=0;
    if(run_ai_analysis(target, "scan_data", &ai_results, &ai_count)!=0) {
        fprintf(stderr, "[!] AI analysis failed\n");
    }
    
    size_t total = recon_count + vuln_count + ai_count;
    module_result_t *all = calloc(total, sizeof(module_result_t));
    if(!all) { 
        free_results(recon, recon_count); 
        free_results(vuln, vuln_count);
        free_results(ai_results, ai_count);
        return; 
    }
    
    for(size_t i=0;i<recon_count;i++) all[i]=recon[i];
    for(size_t j=0;j<vuln_count;j++) all[recon_count+j]=vuln[j];
    for(size_t k=0;k<ai_count;k++) all[recon_count+vuln_count+k]=ai_results[k];
    
    free(recon); free(vuln); free(ai_results);
    
    // Use secure memory reporting in ghost mode
    if (is_ghost_mode()) {
        char* memory_report = generate_memory_report(all, total, target);
        if (memory_report) {
            printf("\n=== SECURE IN-MEMORY REPORT ===\n");
            printf("%s", memory_report);
            printf("=== END SECURE REPORT ===\n\n");
            secure_free(memory_report, strlen(memory_report) + 1);
        }
        printf("[GHOST] Scan complete. No files created. No traces left.\n");
    } else {
        // Legacy file reporting mode
        ensure_reports_dir();
        if(run_report(all, total, target) != 0) {
            fprintf(stderr, "[!] Report generation failed\n");
        }
    }
    
    free_results(all, total);
}

static void run_single(const char *target, int which) {
    module_result_t *res=NULL; size_t count=0;
    int rc = -1;
    
    switch(which) {
        case 1: rc = run_recon(target,&res,&count); break;
        case 2: rc = run_vuln(target,&res,&count); break;
        case 3: rc = run_ai_analysis(target,"scan_data",&res,&count); break;
    }
    
    if(rc!=0) { fprintf(stderr, "[!] Module failed\n"); return; }
    for(size_t i=0;i<count;i++) {
        printf("%s: %s\n", res[i].name, res[i].data);
    }
    free_results(res, count);
}

int main(int argc, char **argv) {
    // Initialize enterprise security controls
    initialize_security_controls();
    
    // Check professional authorization for organizational use
    if (!check_professional_authorization()) {
        secure_organizational_cleanup();
        return 1;
    }
    
    char target[256];
    
    // Check for ghost mode override
    int ghost_disabled = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--no-ghost") == 0 || strcmp(argv[i], "-ng") == 0) {
            ghost_disabled = 1;
            set_ghost_mode(0);
            printf("[WARNING] Ghost mode DISABLED - files will be created!\n");
        }
    }
    
    // Set target with validation
    if(argc > 1 && !ghost_disabled) {
        if (!validate_target_input(argv[1])) {
            printf("[ERROR] Invalid target format or potentially malicious input\n");
            secure_organizational_cleanup();
            return 1;
        }
        strncpy(target, argv[1], sizeof(target)-1); 
        target[sizeof(target)-1] = '\0';
    } else if (argc > 2 && ghost_disabled) {
        if (!validate_target_input(argv[2])) {
            printf("[ERROR] Invalid target format or potentially malicious input\n");
            secure_organizational_cleanup();
            return 1;
        }
        strncpy(target, argv[2], sizeof(target)-1); 
        target[sizeof(target)-1] = '\0';
    } else {
        strcpy(target, "example.com");
    }
    
    printf("SecureScan Pro - Professional Penetration Testing Suite\n");
    printf("Licensed to: %s\n", get_authorized_organization());
    if (is_running_from_removable_media()) {
        printf("=== PORTABLE MODE - USB EXECUTION ===\n");
    }
    if (is_ghost_mode()) {
        printf("=== GHOST MODE ACTIVE - NO ARTIFACTS ===\n");
    } else {
        printf("=== FILE MODE - REPORTS WILL BE SAVED ===\n");
    }
    printf("=============================================\n");
    for(;;) {
        printf("\nTarget: %s\n", target);
        printf("[1] Recon only\n[2] Vulnerability scan only\n[3] AI/ML Analysis\n[4] Full workflow (recon+vuln+AI+report)\n[5] Change target\n[0] Exit\n> ");
        fflush(stdout);
        int choice=-1; if(scanf("%d", &choice)!=1) { break; }
        if(choice==0) break;
        if(choice==5) {
            printf("Enter new target: "); fflush(stdout);
            scanf("%255s", target);
            continue;
        }
        switch(choice) {
            case 1: run_single(target,1); break;
            case 2: run_single(target,2); break;
            case 3: run_single(target,3); break;
            case 4: run_full(target); break;
            default: printf("Invalid option\n"); break;
        }
    }
    
    // Secure cleanup on exit
    if (is_ghost_mode()) {
        clear_artifacts();
        printf("[GHOST] Session terminated. All traces eliminated.\n");
    }
    
    // Secure cleanup before exit (organizational compliance)
    secure_organizational_cleanup();
    return 0;
}
