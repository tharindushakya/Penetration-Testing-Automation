#ifndef VULN_DETECTOR_H
#define VULN_DETECTOR_H

#include "engine.h"
#include <math.h>

// CVSS v3.1 Base Score Calculation Structure
typedef struct {
    double attack_vector;      // Network(0.85), Adjacent(0.62), Local(0.55), Physical(0.2)
    double attack_complexity;  // Low(0.77), High(0.44)
    double privileges_required; // None(0.85), Low(0.62), High(0.27)
    double user_interaction;   // None(0.85), Required(0.62)
    double scope;              // Unchanged(6.42), Changed(7.52)
    double confidentiality;    // High(0.56), Low(0.22), None(0)
    double integrity;          // High(0.56), Low(0.22), None(0)
    double availability;       // High(0.56), Low(0.22), None(0)
} cvss_metrics_t;

// Real vulnerability database entry
typedef struct {
    char *cve_id;              // CVE-2021-44228
    char *cwe_id;              // CWE-502
    double cvss_score;         // CVSS v3.1 base score (0.0-10.0)
    cvss_metrics_t cvss_metrics;
    char *description;
    char *affected_versions;   // Version patterns
    double exploit_probability; // Mathematical probability (0.0-1.0)
    time_t published_date;     // Unix timestamp
    time_t last_modified;      // Unix timestamp
    int severity_level;        // 1=Low, 2=Medium, 3=High, 4=Critical
} vulnerability_entry_t;

// Detection result with mathematical confidence
typedef struct {
    char *vulnerability_id;
    double confidence_score;    // Statistical confidence (0.0-1.0)
    double risk_score;         // Mathematical risk assessment (0.0-10.0)
    char *detection_method;    // Pattern matching, version analysis, etc.
    char *remediation_advice;
    vulnerability_entry_t *vuln_details;
} vuln_detection_t;

// Hybrid detection result combining rule-based and CVE analysis
typedef struct {
    char *detection_id;
    char *detection_type;      // "RULE-BASED", "CVE-ANALYSIS", "HYBRID-FUSION"
    double confidence_score;   // Combined confidence (0.0-1.0)
    double risk_score;         // Integrated risk score (0.0-10.0)
    char *description;
    char *remediation_advice;
    
    // Research-based scoring (2023+ papers)
    double graph_neural_score; // Graph Neural Network confidence
    double transformer_score;  // Transformer-based pattern matching
    double ensemble_score;     // Ensemble learning result
    double explainability_score; // XAI explainability metric
} hybrid_detection_t;

// Mathematical risk assessment
typedef struct {
    double base_score;         // CVSS base score
    double temporal_score;     // Time-based adjustments
    double environmental_score; // Environment-specific factors
    double composite_risk;     // Final calculated risk
    double detection_accuracy; // Statistical accuracy (0.0-1.0)
    
    // Research-enhanced metrics (2023+ papers)
    double attention_weight;   // Attention mechanism weight
    double uncertainty_score;  // Epistemic uncertainty estimation
    double adversarial_robustness; // Adversarial attack resilience
} risk_assessment_t;

// Initialize hybrid vulnerability detection engine
int init_vulnerability_detector(void);

// Mathematical CVSS calculation
double calculate_cvss_base_score(const cvss_metrics_t *metrics);
double calculate_temporal_score(double base_score, double exploitability, double remediation_level);
double calculate_environmental_score(double base_score, double target_distribution);

// Statistical confidence calculation
double calculate_detection_confidence(const char *pattern, const char *data, int pattern_specificity);
double calculate_version_match_probability(const char *detected_version, const char *vulnerable_range);

// Research-based algorithms (2023+ papers)
double calculate_graph_neural_score(const char *service_data, const char *pattern);
double calculate_transformer_attention(const char *context, const char *target_pattern);
double calculate_ensemble_prediction(double rule_score, double cve_score, double ml_score);
double calculate_uncertainty_estimation(double prediction, double variance);

// Hybrid detection systems
int run_hybrid_detection(const char *target_data, hybrid_detection_t **detections, size_t *detection_count);
int run_rule_based_detection(const char *target_data, hybrid_detection_t **detections, size_t *detection_count);
int run_vulnerability_detection(const char *target_data, vuln_detection_t **detections, size_t *detection_count);
int analyze_network_patterns(const char *scan_data, vuln_detection_t **detections, size_t *detection_count);
int detect_service_anomalies(const char *service_data, vuln_detection_t **detections, size_t *detection_count);

// Mathematical risk scoring
risk_assessment_t calculate_comprehensive_risk(const vuln_detection_t *detection);

// Statistical analysis functions
double calculate_false_positive_rate(int true_positives, int false_positives);
double calculate_threat_probability(double cvss_score, double exploit_availability, double patch_age_days);

// System management functions
int init_vulnerability_detector(void);
int analyze_vulnerability(const char *target_data, vuln_detection_t **out_detections, size_t *out_count);
int analyze_network_vulnerability(const char *scan_data, vuln_detection_t **out_detections, size_t *out_count);
void cleanup_vulnerability_detector(void);

#endif // VULN_DETECTOR_H
