#ifndef SECURE_OPS_H
#define SECURE_OPS_H

#include "engine.h"
#include <stddef.h>

// Secure memory operations
void* secure_malloc(size_t size);
void secure_free(void* ptr, size_t size);
char* secure_strdup(const char* src);

// Ghost mode operations
int is_ghost_mode(void);
void set_ghost_mode(int enabled);

// In-memory reporting (no file artifacts)
char* generate_memory_report(module_result_t* results, size_t count, const char* target);

// Anti-forensics
void clear_artifacts(void);
void secure_shutdown(void);

#endif
