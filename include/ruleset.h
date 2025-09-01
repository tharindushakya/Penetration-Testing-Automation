#ifndef RULESET_H
#define RULESET_H

#include <stddef.h>

/* Simple pattern rule */
typedef struct {
    const char *id;      /* RULE-XXXX */
    const char *pattern; /* substring to find */
    const char *desc;    /* description */
    int severity;        /* 1=low 5=critical */
} rule_t;

const rule_t *get_rules(size_t *out_count);

#endif
