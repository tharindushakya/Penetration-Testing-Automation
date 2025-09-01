#include "engine.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    const char *target = (argc>1)?argv[1]:"example.com";

    module_result_t *recon=NULL; size_t recon_count=0;
    if(run_recon(target, &recon, &recon_count)!=0) {
        fprintf(stderr, "Recon failed\n");
        return 1;
    }

    module_result_t *vuln=NULL; size_t vuln_count=0;
    if(run_vuln(target, &vuln, &vuln_count)!=0) {
        fprintf(stderr, "Vuln scan failed\n");
        free_results(recon, recon_count);
        return 2;
    }

    size_t total = recon_count + vuln_count;
    module_result_t *all = calloc(total, sizeof(module_result_t));
    if(!all) return 3;
    for(size_t i=0;i<recon_count;i++) all[i]=recon[i];
    for(size_t j=0;j<vuln_count;j++) all[recon_count+j]=vuln[j];
    free(recon); free(vuln);

    if(run_report(all, total, "reports/report.json")!=0) {
        fprintf(stderr, "Report generation failed\n");
    } else {
        printf("Report written to reports/report.json (target=%s)\n", target);
    }

    free_results(all, total);
    return 0;
}
