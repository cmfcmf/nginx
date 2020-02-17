#ifndef CMFCMF_H_
#define CMFCMF_H_

void cmfcmf_log_access(
    char *name,
    char *type,
    char *field,
    char *file,
    unsigned int line,
    void *object,
    unsigned int pointerLevel);
void cmfcmf_log_modified(
    char *name,
    char *type,
    char *field,
    char *file,
    unsigned int line,
    void *object,
    unsigned int pointerLevel);

#endif