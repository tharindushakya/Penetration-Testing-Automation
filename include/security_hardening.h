/*
 * Security Hardening Header
 * Professional Penetration Testing Suite
 */

#ifndef SECURITY_HARDENING_H
#define SECURITY_HARDENING_H

// Security initialization
void initialize_security_controls(void);

// Input validation
int validate_target_input(const char* target);

// Professional authorization
int check_professional_authorization(void);
int is_professionally_authorized(void);
const char* get_authorized_organization(void);

// Organizational compliance
void secure_organizational_cleanup(void);

// Portable execution
int is_running_from_removable_media(void);

// Anti-analysis protection
int detect_analysis_environment(void);

// Integrity verification
int verify_integrity(void);

// License validation
int validate_professional_license(const char* org_name, const char* license);

#endif // SECURITY_HARDENING_H
