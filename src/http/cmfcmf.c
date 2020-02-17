#include <stdio.h>
#include <cmfcmf.h>
#include <ngx_http.h>

static void* getPointer(void *object, unsigned int pointerLevel) {
    // pointerLevel = 0 -> &a
    // pointerLevel = 1 -> &*a
    // pointerLevel = 2 -> &**a
    for (unsigned int i = 0; i < pointerLevel; i++) {
       object = object == NULL ? NULL : *(void**)object;
    }
    return object;
}

// TODO: This only works when compiling with clang >=7.0.1 and the following flags:
// -ftrivial-auto-var-init=zero
// -enable-trivial-auto-var-init-zero-knowing-it-will-be-removed-from-clang
//
// We should instead not log accesses to not yet initialized variables.
static void append_special_info(char *type, void *object) {
    if (strcmp(type, "ngx_http_request_t") == 0) {
        printf("|%u", ((ngx_http_request_t*)object)->cmf_id);
    } else if (strcmp(type, "ngx_conf_t") == 0) {
        ngx_conf_t *conf = (ngx_conf_t*)object;
        if (conf == NULL) {
            return;
        }
        ngx_conf_file_t *file = conf->conf_file;
        if (file == NULL) {
            return;
        }

        printf("|name=%s,args=%lu,conf_file_name=%s,conf_file_line=%lu",
            conf->name == NULL ? "nil" : conf->name,
            conf->args == NULL ? 0 : conf->args->nelts,
            file->file.name.data == NULL ? "nil" : (char*)file->file.name.data,
            file->line
        );
    }
}

void cmfcmf_log_access(char *name, char *type, char *field, char *file,
                       unsigned int line, void *object, unsigned int pointerLevel) {
    object = getPointer(object, pointerLevel);
    printf("ACCESS|%s|%s|%s|%s|%u|%p",
           name, type, field, file, line, object);
    append_special_info(type, object);
    fputc('\n', stdout);
}

void cmfcmf_log_modified(char *name, char *type, char *field, char *file,
                         unsigned int line, void *object, unsigned int pointerLevel) {
    object = getPointer(object, pointerLevel);
    printf("MODIFIED|%s|%s|%s|%s|%u|%p",
           name, type, field, file, line, object);
    append_special_info(type, object);
    fputc('\n', stdout);
}