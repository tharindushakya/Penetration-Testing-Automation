#include "engine.h"
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

static void ensure_reports_dir(void) {
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
    
    ensure_reports_dir();
    if(run_report(all, total, target) != 0) {
        fprintf(stderr, "[!] Report generation failed\n");
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
    char target[256];
    if(argc>1) {
        strncpy(target, argv[1], sizeof(target)-1); target[sizeof(target)-1]='\0';
    } else {
        strcpy(target, "example.com");
    }
    printf("SecureScan Pro - Penetration Testing Suite (CLI)\n");
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
    return 0;
}
