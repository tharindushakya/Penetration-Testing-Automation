/*
 * Security Hardening Header
 * Open Source Penetration Testing Suite
 */

#ifndef SECURITY_HARDENING_H
#define SECURITY_HARDENING_H

// Security initialization
void initialize_security_controls(void);

// Input validation
int validate_target_input(const char* target);

// System cleanup
void secure_organizational_cleanup(void);

// Portable execution
int is_running_from_removable_media(void);

// Anti-analysis protection
int detect_analysis_environment(void);

// Integrity verification
int verify_integrity(void);

#endif // SECURITY_HARDENING_H
