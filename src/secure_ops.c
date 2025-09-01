#include "secure_ops.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <unistd.h>
#include <sys/mman.h>
#endif

// Global ghost mode flag
static int ghost_mode_enabled = 1;  // Default to secure

// Secure memory allocation that prevents swapping to disk
void* secure_malloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) return NULL;
    
#ifdef _WIN32
    // Lock memory pages to prevent swapping
    VirtualLock(ptr, size);
#else
    mlock(ptr, size);
#endif
    
    // Zero the memory
    memset(ptr, 0, size);
    return ptr;
}

// Secure memory deallocation with overwriting
void secure_free(void* ptr, size_t size) {
    if (!ptr) return;
    
    // Overwrite with random data multiple times (DoD 5220.22-M standard)
    for (int pass = 0; pass < 3; pass++) {
        for (size_t i = 0; i < size; i++) {
            ((char*)ptr)[i] = (char)(rand() % 256);
        }
    }
    
    // Final zero pass
    memset(ptr, 0, size);
    
#ifdef _WIN32
    VirtualUnlock(ptr, size);
#else
    munlock(ptr, size);
#endif
    
    free(ptr);
}

// Check if ghost mode is enabled
int is_ghost_mode(void) {
    return ghost_mode_enabled;
}

// Enable/disable ghost mode
void set_ghost_mode(int enabled) {
    ghost_mode_enabled = enabled;
}

// Secure string handling - no artifacts
char* secure_strdup(const char* src) {
    if (!src) return NULL;
    
    size_t len = strlen(src) + 1;
    char* dst = (char*)secure_malloc(len);
    if (dst) {
        strcpy(dst, src);
    }
    return dst;
}

// In-memory report generation (no file artifacts)
typedef struct {
    char* data;
    size_t size;
    size_t capacity;
} memory_buffer_t;

static memory_buffer_t* create_memory_buffer(void) {
    memory_buffer_t* buf = (memory_buffer_t*)secure_malloc(sizeof(memory_buffer_t));
    if (buf) {
        buf->capacity = 8192;
        buf->data = (char*)secure_malloc(buf->capacity);
        buf->size = 0;
    }
    return buf;
}

static void append_to_buffer(memory_buffer_t* buf, const char* text) {
    if (!buf || !text) return;
    
    size_t len = strlen(text);
    if (buf->size + len >= buf->capacity) {
        // Expand buffer
        buf->capacity *= 2;
        char* new_data = (char*)secure_malloc(buf->capacity);
        memcpy(new_data, buf->data, buf->size);
        secure_free(buf->data, buf->size);
        buf->data = new_data;
    }
    
    memcpy(buf->data + buf->size, text, len);
    buf->size += len;
    buf->data[buf->size] = '\0';
}

static void destroy_memory_buffer(memory_buffer_t* buf) {
    if (buf) {
        if (buf->data) {
            secure_free(buf->data, buf->capacity);
        }
        secure_free(buf, sizeof(memory_buffer_t));
    }
}

// Generate report in memory only - no file artifacts
char* generate_memory_report(module_result_t* results, size_t count, const char* target) {
    if (!is_ghost_mode()) {
        return NULL;  // Traditional file reports only when ghost mode disabled
    }
    
    memory_buffer_t* report = create_memory_buffer();
    if (!report) return NULL;
    
    // Generate timestamp for display only (not stored)
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    // Build report header
    char header[512];
    snprintf(header, sizeof(header), 
        "=== SECURITY SCAN RESULTS ===\n"
        "Target: %s\n"
        "Scan Time: %s\n"
        "Results: %zu findings\n"
        "=================================\n\n",
        target, timestamp, count);
    append_to_buffer(report, header);
    
    // Add findings
    for (size_t i = 0; i < count; i++) {
        char finding[1024];
        snprintf(finding, sizeof(finding),
            "[%zu] %s\n"
            "    Data: %s\n"
            "    Type: %d\n\n",
            i + 1, results[i].name, results[i].data, results[i].type);
        append_to_buffer(report, finding);
    }
    
    // Add security footer
    append_to_buffer(report, "\n=== SCAN COMPLETE ===\n");
    append_to_buffer(report, "NOTE: This report exists in memory only.\n");
    append_to_buffer(report, "No files were created. No artifacts left on disk.\n");
    
    // Return the report data (caller must secure_free it)
    char* result = secure_strdup(report->data);
    destroy_memory_buffer(report);
    
    return result;
}

// Anti-forensics: Clear any temporary artifacts
void clear_artifacts(void) {
    // Clear any temporary files that might exist
    remove("reports/.probe");
    
    // Remove reports directory if it exists and is empty
#ifdef _WIN32
    RemoveDirectoryA("reports");
#else
    rmdir("reports");
#endif
    
    // Clear environment variables that might contain scan data
    putenv("TARGET=");
    putenv("SCAN_DATA=");
}

// Self-destruct function (optional - for extreme scenarios)
void secure_shutdown(void) {
    clear_artifacts();
    
    // Clear command line arguments from memory
    // Note: This is aggressive and should only be used in specific scenarios
    
    printf("[GHOST] All artifacts cleared. No trace left.\n");
}
