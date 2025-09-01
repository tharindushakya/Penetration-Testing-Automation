#ifndef ENGINE_H
#define ENGINE_H

#include <stddef.h>

typedef enum { MODULE_RECON, MODULE_VULN, MODULE_REPORT } module_type_t;

typedef struct module_result {
    module_type_t type;
    char *name;
    char *data; /* dynamically allocated textual data */
} module_result_t;

int run_recon(const char *target, module_result_t **out_results, size_t *out_count);
int run_vuln(const char *target, module_result_t **out_results, size_t *out_count);
int run_report(module_result_t *all_results, size_t count, const char *target);

void free_results(module_result_t *results, size_t count);

#endif /* ENGINE_H */
