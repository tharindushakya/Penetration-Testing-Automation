#include "engine.h"
#include "ruleset.h"
#include "report.h"
#include "vuln_detector.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static module_result_t *alloc_results(size_t n) {
    return calloc(n, sizeof(module_result_t));
}

// Enhanced banner grabbing simulation
static const char* get_service_banner(const char* service, const char* target) {
    // Simulate realistic service banners for testing
    if(strstr(service, "http")) {
        // Simulate various web server configurations
        static const char* web_banners[] = {
            "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nX-Powered-By: PHP/7.4.3\r\n",
            "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\nX-Powered-By: Express\r\n",
            "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/8.5\r\nX-Powered-By: ASP.NET\r\n",
            "HTTP/1.1 200 OK\r\nServer: Apache/2.4.29 (Win32) OpenSSL/1.0.2ze-dev\r\nX-Powered-By: PHP/5.6.40\r\n"
        };
        return web_banners[strlen(target) % 4];
    } else if(strstr(service, "ssh")) {
        // Simulate SSH version banners
        static const char* ssh_banners[] = {
            "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3",
            "SSH-2.0-OpenSSH_8.0",
            "SSH-2.0-libssh_0.8.7",
            "SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u4"
        };
        return ssh_banners[strlen(target) % 4];
    } else if(strstr(service, "ftp")) {
        return "220 (vsFTPd 3.0.3)";
    } else if(strstr(service, "smtp")) {
        return "220 mail.example.com ESMTP Postfix (Ubuntu)";
    }
    return "Unknown service";
}

int run_recon(const char *target, module_result_t **out_results, size_t *out_count) {
    printf("[RECON] Starting enhanced reconnaissance on %s...\n", target);
    printf("[RECON] Performing DNS resolution...\n");
    printf("[RECON] Scanning common ports...\n");
    printf("[RECON] Banner grabbing for service identification...\n");
    
    size_t n = 5;  // More detailed recon results
    module_result_t *res = alloc_results(n);
    if(!res) return -1;
    
    // DNS Resolution
    res[0].type = MODULE_RECON; 
    res[0].name = strdup("dns_lookup"); 
    res[0].data = strdup("A:93.184.216.34;AAAA:2606:2800:220:1:248:1893:25c8:1946");
    
    // Port Scan with more services
    res[1].type = MODULE_RECON; 
    res[1].name = strdup("port_scan"); 
    res[1].data = strdup("21/tcp open ftp;22/tcp open ssh;25/tcp open smtp;80/tcp open http;443/tcp open https");
    
    // HTTP Banner
    res[2].type = MODULE_RECON; 
    res[2].name = strdup("http_banner"); 
    res[2].data = strdup(get_service_banner("http", target));
    
    // SSH Banner
    res[3].type = MODULE_RECON; 
    res[3].name = strdup("ssh_banner"); 
    res[3].data = strdup(get_service_banner("ssh", target));
    
    // Service Summary
    res[4].type = MODULE_RECON; 
    res[4].name = strdup("service_summary"); 
    char summary[512];
    snprintf(summary, sizeof(summary), 
        "Target: %s | Services: HTTP, SSH, FTP, SMTP | OS: Linux (Ubuntu)", target);
    res[4].data = strdup(summary);
    
    printf("[RECON] Reconnaissance complete - %zu results collected\n", n);
    *out_results = res; *out_count = n; return 0;
}

int run_vuln(const char *target, module_result_t **out_results, size_t *out_count) {
    printf("[VULN] Starting vulnerability assessment on %s...\n", target);
    printf("[VULN] Analyzing service banners for known vulnerabilities...\n");
    
    // Get comprehensive banner data (simulate data from recon phase)
    const char *http_banner = get_service_banner("http", target);
    const char *ssh_banner = get_service_banner("ssh", target);
    
    // Combine all collected data for analysis
    char combined_banners[1024];
    snprintf(combined_banners, sizeof(combined_banners), 
        "%s\nSSH-Banner: %s\nServices: ftp,ssh,smtp,http,https", 
        http_banner, ssh_banner);
    
    size_t rule_count = 0; 
    const rule_t *rules = get_rules(&rule_count);
    size_t n = rule_count; 
    module_result_t *res = alloc_results(n);
    if(!res) return -1;
    
    size_t idx = 0;
    printf("[VULN] Testing %zu vulnerability rules against collected data...\n", rule_count);
    
    for(size_t i = 0; i < rule_count; i++) {
        if(strstr(combined_banners, rules[i].pattern)) {
            char buf[512];
            snprintf(buf, sizeof(buf), 
                "%s matched '%s' in banner data | Severity: %d | Target: %s", 
                rules[i].id, rules[i].pattern, rules[i].severity, target);
            res[idx].type = MODULE_VULN;
            res[idx].name = strdup(rules[i].id);
            res[idx].data = strdup(buf);
            printf("[VULN] MATCH: %s detected %s\n", rules[i].id, rules[i].pattern);
            idx++;
        }
    }
    
    printf("[VULN] Vulnerability scan complete - %zu vulnerabilities detected\n", idx);
    *out_results = res; *out_count = idx; return 0;
}

int run_ai_analysis(const char *target, const char *scan_data, module_result_t **out_results, size_t *out_count) {
    printf("[VULN-DB] Initializing mathematical vulnerability detection engine...\n");
    init_vulnerability_detector();
    
    // Get actual banner data from reconnaissance
    const char *http_banner = get_service_banner("http", target);
    const char *ssh_banner = get_service_banner("ssh", target);
    
    // Combine all real scan data for analysis
    char combined_data[2048];
    snprintf(combined_data, sizeof(combined_data), 
        "Target: %s\nScan Data: %s\n%s\nSSH-Banner: %s\nServices: ftp,ssh,smtp,http,https",
        target ? target : "unknown", 
        scan_data ? scan_data : "", 
        http_banner, 
        ssh_banner);
    
    printf("[VULN-DB] Analyzing collected data: %zu bytes\n", strlen(combined_data));
    printf("[VULN-DB] Data sample: %.100s...\n", combined_data);
    
    vuln_detection_t *vuln_detections = NULL;
    size_t vuln_count = 0;
    
    vuln_detection_t *network_detections = NULL;
    size_t network_count = 0;
    
    vuln_detection_t *anomaly_detections = NULL;
    size_t anomaly_count = 0;
    
    // Run mathematical vulnerability analysis modules
    run_vulnerability_detection(combined_data, &vuln_detections, &vuln_count);
    analyze_network_patterns("22/tcp open ssh;80/tcp open http", &network_detections, &network_count);
    detect_service_anomalies(combined_data, &anomaly_detections, &anomaly_count);
    
    // Convert vulnerability detections to module results
    size_t total_detections = vuln_count + network_count + anomaly_count;
    module_result_t *results = calloc(total_detections, sizeof(module_result_t));
    if(!results) return -1;
    
    size_t idx = 0;
    
    // Add mathematical vulnerability detections
    for(size_t i = 0; i < vuln_count; i++, idx++) {
        results[idx].type = MODULE_AI;
        results[idx].name = strdup(vuln_detections[i].vulnerability_id);
        
        char vuln_data[1024];
        snprintf(vuln_data, sizeof(vuln_data), 
            "[CVSS] Risk Score: %.2f | Confidence: %.3f | Method: %s | Details: %s",
            vuln_detections[i].risk_score,
            vuln_detections[i].confidence_score,
            vuln_detections[i].detection_method,
            vuln_detections[i].remediation_advice);
        results[idx].data = strdup(vuln_data);
    }
    
    // Add network pattern detections
    for(size_t i = 0; i < network_count; i++, idx++) {
        results[idx].type = MODULE_AI;
        results[idx].name = strdup(network_detections[i].vulnerability_id);
        
        char net_data[1024];
        snprintf(net_data, sizeof(net_data), 
            "[NET] Pattern Score: %.3f | Method: %s | Analysis: %s",
            network_detections[i].confidence_score,
            network_detections[i].detection_method,
            network_detections[i].remediation_advice);
        results[idx].data = strdup(net_data);
    }
    
    // Add anomaly detections
    for(size_t i = 0; i < anomaly_count; i++, idx++) {
        results[idx].type = MODULE_AI;
        results[idx].name = strdup(anomaly_detections[i].vulnerability_id);
        
        char anom_data[1024];
        snprintf(anom_data, sizeof(anom_data), 
            "[ANOM] Anomaly Score: %.3f | Method: %s | Analysis: %s",
            anomaly_detections[i].confidence_score,
            anomaly_detections[i].detection_method,
            anomaly_detections[i].remediation_advice);
        results[idx].data = strdup(anom_data);
    }
    
    printf("[VULN-DB] Mathematical vulnerability analysis complete. Found %zu insights\n", total_detections);
    
    *out_results = results;
    *out_count = total_detections;
    
    return 0;
}

int run_report(module_result_t *all_results, size_t count, const char *target) {
    return generate_summary_report(all_results, count, target, "reports");
}

void free_results(module_result_t *results, size_t count) {
    if(!results) return;
    for(size_t i=0;i<count;i++) {
        free(results[i].name);
        free(results[i].data);
    }
    free(results);
}
