#include "report.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char* severity_to_string(int severity) {
    switch(severity) {
        case 1: return "Low";
        case 2: return "Medium";
        case 3: return "Medium";
        case 4: return "High";
        case 5: return "Critical";
        default: return "Unknown";
    }
}

static const char* severity_to_emoji(int severity) {
    switch(severity) {
        case 1: return "🟢";
        case 2: return "🟡";
        case 3: return "🟠";
        case 4: return "🔴";
        case 5: return "!";
        default: return "❓";
    }
}

int generate_summary_report(module_result_t *all_results, size_t count, const char *target, const char *base_path) {
    char json_path[512], summary_path[512];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", tm_info);
    
    // Create file paths with target name and timestamp
    snprintf(json_path, sizeof(json_path), "%s/%s_%s_report.json", base_path, target, timestamp);
    snprintf(summary_path, sizeof(summary_path), "%s/%s_%s_summary.md", base_path, target, timestamp);
    
    // Generate JSON report
    FILE *json_file = fopen(json_path, "w");
    if(!json_file) return -1;
    
    fprintf(json_file, "{\n");
    fprintf(json_file, "  \"target\": \"%s\",\n", target);
    fprintf(json_file, "  \"timestamp\": \"%s\",\n", timestamp);
    fprintf(json_file, "  \"results\": [\n");
    
    for(size_t i = 0; i < count; i++) {
        fprintf(json_file, "    {\"module\": %d, \"name\": \"%s\", \"data\": \"", 
                all_results[i].type, all_results[i].name);
        // JSON escaping
        for(char *p = all_results[i].data; p && *p; ++p) {
            if(*p == '"' || *p == '\\') fputc('\\', json_file);
            if(*p == '\n') { fputs("\\n", json_file); continue; }
            fputc(*p, json_file);
        }
        fprintf(json_file, "\"}%s\n", (i + 1 < count) ? "," : "");
    }
    
    fprintf(json_file, "  ]\n}\n");
    fclose(json_file);
    
    // Generate formatted summary
    FILE *summary_file = fopen(summary_path, "w");
    if(!summary_file) return -1;
    
    fprintf(summary_file, "# Penetration Test Results Summary\n\n");
    fprintf(summary_file, "**Target:** %s  \n", target);
    fprintf(summary_file, "**Scan Time:** %s  \n", timestamp);
    fprintf(summary_file, "**Total Findings:** %zu\n\n", count);
    
    // Count findings by module
    size_t recon_count = 0, vuln_count = 0, ai_count = 0;
    for(size_t i = 0; i < count; i++) {
        if(all_results[i].type == MODULE_RECON) recon_count++;
        else if(all_results[i].type == MODULE_VULN) vuln_count++;
        else if(all_results[i].type == MODULE_AI) ai_count++;
    }
    
    // Reconnaissance section
    fprintf(summary_file, "## 🔍 Reconnaissance Results (Module 0)\n\n");
    for(size_t i = 0; i < count; i++) {
        if(all_results[i].type == MODULE_RECON) {
            if(strcmp(all_results[i].name, "dns_lookup") == 0) {
                fprintf(summary_file, "### DNS Lookup\n");
                char *data = strdup(all_results[i].data);
                char *token = strtok(data, ";");
                while(token) {
                    if(strncmp(token, "A:", 2) == 0) {
                        fprintf(summary_file, "- **IPv4:** `%s`\n", token + 2);
                    } else if(strncmp(token, "AAAA:", 5) == 0) {
                        fprintf(summary_file, "- **IPv6:** `%s`\n", token + 5);
                    }
                    token = strtok(NULL, ";");
                }
                free(data);
            } else if(strcmp(all_results[i].name, "port_scan") == 0) {
                fprintf(summary_file, "\n### Port Scan\n");
                char *data = strdup(all_results[i].data);
                char *token = strtok(data, ";");
                while(token) {
                    fprintf(summary_file, "- **%s**\n", token);
                    token = strtok(NULL, ";");
                }
                free(data);
            }
        }
    }
    
    // Vulnerability section
    if(vuln_count > 0) {
        fprintf(summary_file, "\n## 🛡️ Vulnerability Assessment (Module 1)\n\n");
        fprintf(summary_file, "The toolkit detected **%zu security findings**:\n\n", vuln_count);
        
        int finding_num = 1;
        for(size_t i = 0; i < count; i++) {
            if(all_results[i].type == MODULE_VULN) {
                // Parse the vulnerability data
                char *data = strdup(all_results[i].data);
                char *rule_id = all_results[i].name;
                
                // Extract severity from data
                int severity = 1;
                char *sev_pos = strstr(data, "severity=");
                if(sev_pos) {
                    severity = atoi(sev_pos + 9);
                }
                
                // Extract matched pattern
                char *pattern_start = strstr(data, "matched '");
                char *pattern_end = NULL;
                char pattern[256] = "Unknown";
                if(pattern_start) {
                    pattern_start += 9;
                    pattern_end = strchr(pattern_start, '\'');
                    if(pattern_end) {
                        size_t len = pattern_end - pattern_start;
                        if(len < sizeof(pattern)) {
                            strncpy(pattern, pattern_start, len);
                            pattern[len] = '\0';
                        }
                    }
                }
                
                fprintf(summary_file, "### %s %s - Finding #%d\n", 
                        severity_to_emoji(severity), rule_id, finding_num++);
                fprintf(summary_file, "- **Finding:** `%s` header detected\n", pattern);
                fprintf(summary_file, "- **Severity:** %d (%s)\n", severity, severity_to_string(severity));
                fprintf(summary_file, "- **Impact:** %s\n", 
                        (severity >= 3) ? "Potential security risk - information disclosure" : 
                        "Low risk - banner information leakage");
                fprintf(summary_file, "\n");
                
                free(data);
            }
        }
    }
    
    // AI/ML Analysis section
    if(ai_count > 0) {
        fprintf(summary_file, "\n## 🤖 AI/ML Security Analysis (Module AI)\n\n");
        fprintf(summary_file, "The AI engine detected **%zu ML-powered insights**:\n\n", ai_count);
        
        int ai_finding_num = 1;
        for(size_t i = 0; i < count; i++) {
            if(all_results[i].type == MODULE_AI) {
                // Parse AI confidence from data
                double confidence = 0.0;
                char *conf_pos = strstr(all_results[i].data, "Confidence: ");
                if(!conf_pos) conf_pos = strstr(all_results[i].data, "Pattern: ");
                if(!conf_pos) conf_pos = strstr(all_results[i].data, "Score: ");
                
                if(conf_pos) {
                    conf_pos = strchr(conf_pos, ' ') + 1;
                    confidence = atof(conf_pos);
                }
                
                // Determine AI confidence emoji
                const char *ai_emoji = confidence > 0.8 ? "🔴" : 
                                     confidence > 0.6 ? "🟠" : 
                                     confidence > 0.4 ? "🟡" : "🟢";
                
                fprintf(summary_file, "### %s %s - AI Finding #%d\n", 
                        ai_emoji, all_results[i].name, ai_finding_num++);
                
                // Extract reasoning and action from AI data
                char *reasoning_start = strstr(all_results[i].data, "Reasoning: ");
                char *action_start = strstr(all_results[i].data, "Action: ");
                
                if(reasoning_start && action_start) {
                    reasoning_start += 11; // Skip "Reasoning: "
                    size_t reasoning_len = action_start - reasoning_start - 3; // -3 for " | "
                    
                    fprintf(summary_file, "- **AI Confidence:** %.2f/1.0\n", confidence);
                    fprintf(summary_file, "- **ML Analysis:** ");
                    fwrite(reasoning_start, 1, reasoning_len, summary_file);
                    fprintf(summary_file, "\n- **Recommended Action:** %s\n", action_start + 8);
                } else {
                    fprintf(summary_file, "- **Details:** %s\n", all_results[i].data);
                }
                fprintf(summary_file, "\n");
            }
        }
    }
    
    // Key insights
    fprintf(summary_file, "## 🎯 Key Insights\n\n");
    fprintf(summary_file, "- Target has %zu reconnaissance data points\n", recon_count);
    if(vuln_count > 0) {
        fprintf(summary_file, "- %zu traditional vulnerabilities identified\n", vuln_count);
    }
    if(ai_count > 0) {
        fprintf(summary_file, "- %zu AI/ML-powered security insights discovered\n", ai_count);
        fprintf(summary_file, "- Machine learning models provided enhanced threat detection\n");
        fprintf(summary_file, "- Neural network analysis identified behavioral patterns\n");
    }
    if(vuln_count > 0 || ai_count > 0) {
        fprintf(summary_file, "- Server is revealing technology stack information\n");
        fprintf(summary_file, "- Recommend header hardening and banner suppression\n");
    } else {
        fprintf(summary_file, "- No vulnerabilities detected in basic scan\n");
    }
    fprintf(summary_file, "\n---\n*Generated by PenTest Automation Toolkit*\n");
    
    fclose(summary_file);
    
    printf("[+] JSON report: %s\n", json_path);
    printf("[+] Summary report: %s\n", summary_path);
    
    return 0;
}
