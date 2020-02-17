#include <stdio.h>
#include <cmfcmf.h>
#include <ngx_http.h>

void* getPointer(void *object, unsigned int pointerLevel) {
    // pointerLevel = 0 -> &a
    // pointerLevel = 1 -> &*a
    // pointerLevel = 2 -> &**a
    for (unsigned int i = 0; i < pointerLevel; i++) {
       object = object == NULL ? NULL : *(void**)object;
    }
    return object;
}

void cmfcmf_log_access(char *name, char *type, char *field, char *file,
                       unsigned int line, void *object, unsigned int pointerLevel) {
    object = getPointer(object, pointerLevel);
    printf("ACCESS|%s|%s|%s|%s|%u|%p",
           name, type, field, file, line, object);
    if (strcmp(type, "ngx_http_request_t") == 0) {
        printf("|%u", ((ngx_http_request_t*)object)->cmf_id);
    }
    fputc('\n', stdout);
}

void cmfcmf_log_modified(char *name, char *type, char *field, char *file,
                         unsigned int line, void *object, unsigned int pointerLevel) {
    object = getPointer(object, pointerLevel);
    printf("MODIFIED|%s|%s|%s|%s|%u|%p",
           name, type, field, file, line, object);
    if (strcmp(type, "ngx_http_request_t") == 0) {
        printf("|%u", ((ngx_http_request_t*)object)->cmf_id);
    }
    fputc('\n', stdout);
}