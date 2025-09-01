#ifndef AI_DETECTOR_H
#define AI_DETECTOR_H

#include "engine.h"

typedef struct {
    char *feature_name;
    double weight;
    double threshold;
} ml_feature_t;

typedef struct {
    char *model_name;
    ml_feature_t *features;
    size_t feature_count;
    double confidence_threshold;
} ml_model_t;

typedef struct {
    char *vulnerability_type;
    double confidence_score;
    char *ai_reasoning;
    char *recommended_action;
} ai_detection_t;

// Initialize AI/ML detection engine
int init_ai_detector(void);

// Run AI-powered vulnerability detection
int run_ai_detection(const char *target_data, ai_detection_t **detections, size_t *detection_count);

// Analyze network patterns with ML
int analyze_network_patterns(const char *scan_data, ai_detection_t **detections, size_t *detection_count);

// Behavioral anomaly detection
int detect_service_anomalies(const char *service_banners, ai_detection_t **detections, size_t *detection_count);

// Free AI detection results
void free_ai_detections(ai_detection_t *detections, size_t count);

// Update ML models with new threat intelligence
int update_threat_models(const char *threat_feed_data);

#endif /* AI_DETECTOR_H */
