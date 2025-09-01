#include "ruleset.h"
#include <stdlib.h>

static const rule_t STATIC_RULES[] = {
    {"RULE-0001", "Apache/2", "Apache 2.x detected - check for known CVEs", 2},
    {"RULE-0002", "OpenSSH_7", "OpenSSH 7.x - review for outdated minor versions", 2},
    {"RULE-0003", "PHP/5.6", "Legacy PHP 5.6 exposed", 4},
    {"RULE-0004", "Server: nginx", "Nginx server header present", 1},
    {"RULE-0005", "X-Powered-By: Express", "Express framework header leaks stack info", 3}
};

const rule_t *get_rules(size_t *out_count) {
    if(out_count) *out_count = sizeof(STATIC_RULES)/sizeof(STATIC_RULES[0]);
    return STATIC_RULES;
}
