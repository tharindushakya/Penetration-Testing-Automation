#include "engine.h"
#include "ruleset.h"
#include "report.h"
#include "ai_detector.h"
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

int run_ai_analysis(const char *target, const char *scan_data, module_result_t **out_results, size_t *out_count) {
    (void)target;
    
    printf("[AI] Initializing AI/ML vulnerability detection engine...\n");
    init_ai_detector();
    
    // Combine all scan data for AI analysis
    char combined_data[2048];
    snprintf(combined_data, sizeof(combined_data), 
        "Target: %s\nScan Data: %s\nHeaders: Server: nginx\r\nX-Powered-By: Express\r\n",
        target ? target : "unknown", scan_data ? scan_data : "");
    
    ai_detection_t *ai_detections = NULL;
    size_t ai_count = 0;
    
    ai_detection_t *network_detections = NULL;
    size_t network_count = 0;
    
    ai_detection_t *anomaly_detections = NULL;
    size_t anomaly_count = 0;
    
    // Run multiple AI analysis modules
    run_ai_detection(combined_data, &ai_detections, &ai_count);
    analyze_network_patterns("22/tcp open ssh;80/tcp open http", &network_detections, &network_count);
    detect_service_anomalies(combined_data, &anomaly_detections, &anomaly_count);
    
    // Convert AI detections to module results
    size_t total_detections = ai_count + network_count + anomaly_count;
    module_result_t *results = calloc(total_detections, sizeof(module_result_t));
    if(!results) return -1;
    
    size_t idx = 0;
    
    // Add AI vulnerability detections
    for(size_t i = 0; i < ai_count; i++, idx++) {
        results[idx].type = MODULE_AI;
        results[idx].name = strdup(ai_detections[i].vulnerability_type);
        
        char ai_data[1024];
        snprintf(ai_data, sizeof(ai_data), 
            "[AI] AI Confidence: %.2f | Reasoning: %s | Action: %s",
            ai_detections[i].confidence_score,
            ai_detections[i].ai_reasoning,
            ai_detections[i].recommended_action);
        results[idx].data = strdup(ai_data);
    }
    
    // Add network pattern detections
    for(size_t i = 0; i < network_count; i++, idx++) {
        results[idx].type = MODULE_AI;
        results[idx].name = strdup(network_detections[i].vulnerability_type);
        
        char ai_data[1024];
        snprintf(ai_data, sizeof(ai_data), 
            "[NET] ML Pattern: %.2f | Reasoning: %s | Action: %s",
            network_detections[i].confidence_score,
            network_detections[i].ai_reasoning,
            network_detections[i].recommended_action);
        results[idx].data = strdup(ai_data);
    }
    
    // Add anomaly detections
    for(size_t i = 0; i < anomaly_count; i++, idx++) {
        results[idx].type = MODULE_AI;
        results[idx].name = strdup(anomaly_detections[i].vulnerability_type);
        
        char ai_data[1024];
        snprintf(ai_data, sizeof(ai_data), 
            "[ANOM] Anomaly Score: %.2f | Reasoning: %s | Action: %s",
            anomaly_detections[i].confidence_score,
            anomaly_detections[i].ai_reasoning,
            anomaly_detections[i].recommended_action);
        results[idx].data = strdup(ai_data);
    }
    
    // Update threat models
    update_threat_models("latest_threat_intel.json");
    
    // Cleanup AI detection results
    free_ai_detections(ai_detections, ai_count);
    free_ai_detections(network_detections, network_count);
    free_ai_detections(anomaly_detections, anomaly_count);
    
    printf("[AI] AI analysis complete. Found %zu ML-powered insights\n", total_detections);
    
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
