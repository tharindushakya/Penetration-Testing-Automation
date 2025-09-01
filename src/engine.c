#include "engine.h"
#include "ruleset.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static module_result_t *alloc_results(size_t n) {
    return calloc(n, sizeof(module_result_t));
}

int run_recon(const char *target, module_result_t **out_results, size_t *out_count) {
    (void)target;
    size_t n = 2;
    module_result_t *res = alloc_results(n);
    if(!res) return -1;
    res[0].type = MODULE_RECON; res[0].name = strdup("dns_lookup"); res[0].data = strdup("A:93.184.216.34;AAAA:2606:2800:220:1:248:1893:25c8:1946");
    res[1].type = MODULE_RECON; res[1].name = strdup("port_scan"); res[1].data = strdup("22/tcp open ssh;80/tcp open http");
    *out_results = res; *out_count = n; return 0;
}

int run_vuln(const char *target, module_result_t **out_results, size_t *out_count) {
    (void)target;
    const char *sample_banner = "HTTP/1.1 200 OK\r\nServer: nginx\r\nX-Powered-By: Express\r\n";
    size_t rule_count=0; const rule_t *rules = get_rules(&rule_count);
    size_t n = rule_count; module_result_t *res = alloc_results(n);
    if(!res) return -1;
    size_t idx=0;
    for(size_t i=0;i<rule_count;i++) {
        if(strstr(sample_banner, rules[i].pattern)) {
            char buf[256];
            snprintf(buf, sizeof(buf), "%s matched '%s' severity=%d", rules[i].id, rules[i].pattern, rules[i].severity);
            res[idx].type = MODULE_VULN;
            res[idx].name = strdup(rules[i].id);
            res[idx].data = strdup(buf);
            idx++;
        }
    }
    *out_results = res; *out_count = idx; return 0;
}

int run_report(module_result_t *all_results, size_t count, const char *out_path) {
    FILE *f = fopen(out_path, "w");
    if(!f) return -1;
    fprintf(f, "{\n  \"results\": [\n");
    for(size_t i=0;i<count;i++) {
        fprintf(f, "    {\"module\": %d, \"name\": \"%s\", \"data\": \"", all_results[i].type, all_results[i].name);
        /* naive JSON escaping */
        for(char *p = all_results[i].data; p && *p; ++p) {
            if(*p=='"' || *p=='\\') fputc('\\', f);
            if(*p=='\n') { fputs("\\n", f); continue; }
            fputc(*p, f);
        }
        fprintf(f, "\"}%s\n", (i+1<count)?",":"");
    }
    fprintf(f, "  ]\n}\n");
    fclose(f);
    return 0;
}

void free_results(module_result_t *results, size_t count) {
    if(!results) return;
    for(size_t i=0;i<count;i++) {
        free(results[i].name);
        free(results[i].data);
    }
    free(results);
}
