#!/bin/bash

set -e

./auto/configure \
    --prefix=/tmp/nginx-var
#    --with-debug --with-cc-opt='-O0 -g'


OUTPATH="/tmp"

FILES="
src/core/nginx.c
src/core/ngx_log.c
src/core/ngx_palloc.c
src/core/ngx_array.c
src/core/ngx_list.c
src/core/ngx_hash.c
src/core/ngx_buf.c
src/core/ngx_queue.c
src/core/ngx_output_chain.c
src/core/ngx_string.c
src/core/ngx_parse.c
src/core/ngx_parse_time.c
src/core/ngx_inet.c
src/core/ngx_file.c
src/core/ngx_crc32.c
src/core/ngx_murmurhash.c
src/core/ngx_md5.c
src/core/ngx_sha1.c
src/core/ngx_rbtree.c
src/core/ngx_radix_tree.c
src/core/ngx_slab.c
src/core/ngx_times.c
src/core/ngx_shmtx.c
src/core/ngx_connection.c
src/core/ngx_cycle.c
src/core/ngx_spinlock.c
src/core/ngx_rwlock.c
src/core/ngx_cpuinfo.c
src/core/ngx_conf_file.c
src/core/ngx_module.c
src/core/ngx_resolver.c
src/core/ngx_open_file_cache.c
src/core/ngx_crypt.c
src/core/ngx_proxy_protocol.c
src/core/ngx_syslog.c

src/os/unix/ngx_time.c
src/os/unix/ngx_errno.c
src/os/unix/ngx_alloc.c
src/os/unix/ngx_files.c
src/os/unix/ngx_socket.c
src/os/unix/ngx_recv.c
src/os/unix/ngx_readv_chain.c
src/os/unix/ngx_udp_recv.c
src/os/unix/ngx_send.c
src/os/unix/ngx_writev_chain.c
src/os/unix/ngx_udp_send.c
src/os/unix/ngx_udp_sendmsg_chain.c
src/os/unix/ngx_channel.c
src/os/unix/ngx_shmem.c
src/os/unix/ngx_process.c
src/os/unix/ngx_daemon.c
src/os/unix/ngx_setaffinity.c
src/os/unix/ngx_setproctitle.c
src/os/unix/ngx_posix_init.c
src/os/unix/ngx_user.c
src/os/unix/ngx_dlopen.c
src/os/unix/ngx_process_cycle.c

src/http/ngx_http.c
src/http/ngx_http_core_module.c
src/http/ngx_http_special_response.c
src/http/ngx_http_request.c
src/http/ngx_http_parse.c
src/http/modules/ngx_http_log_module.c
src/http/ngx_http_request_body.c
src/http/ngx_http_variables.c
src/http/ngx_http_script.c
src/http/ngx_http_upstream.c
src/http/ngx_http_upstream_round_robin.c

src/http/ngx_http_file_cache.c
src/http/ngx_http_write_filter_module.c
src/http/ngx_http_header_filter_module.c
src/http/modules/ngx_http_chunked_filter_module.c
src/http/modules/ngx_http_range_filter_module.c
src/http/ngx_http_postpone_filter_module.c
src/http/modules/ngx_http_ssi_filter_module.c
src/http/modules/ngx_http_charset_filter_module.c
src/http/modules/ngx_http_userid_filter_module.c
src/http/modules/ngx_http_headers_filter_module.c
src/http/ngx_http_copy_filter_module.c
src/http/modules/ngx_http_not_modified_filter_module.c
src/http/modules/ngx_http_static_module.c
src/http/modules/ngx_http_autoindex_module.c
src/http/modules/ngx_http_index_module.c
src/http/modules/ngx_http_mirror_module.c
src/http/modules/ngx_http_try_files_module.c
src/http/modules/ngx_http_auth_basic_module.c
src/http/modules/ngx_http_access_module.c
src/http/modules/ngx_http_limit_conn_module.c
src/http/modules/ngx_http_limit_req_module.c
src/http/modules/ngx_http_geo_module.c
src/http/modules/ngx_http_map_module.c
src/http/modules/ngx_http_split_clients_module.c
src/http/modules/ngx_http_referer_module.c
src/http/modules/ngx_http_rewrite_module.c
src/http/modules/ngx_http_proxy_module.c
src/http/modules/ngx_http_fastcgi_module.c
src/http/modules/ngx_http_uwsgi_module.c
src/http/modules/ngx_http_scgi_module.c
src/http/modules/ngx_http_memcached_module.c
src/http/modules/ngx_http_empty_gif_module.c
src/http/modules/ngx_http_browser_module.c
src/http/modules/ngx_http_upstream_hash_module.c
src/http/modules/ngx_http_upstream_ip_hash_module.c
src/http/modules/ngx_http_upstream_least_conn_module.c
src/http/modules/ngx_http_upstream_random_module.c
src/http/modules/ngx_http_upstream_keepalive_module.c
src/http/modules/ngx_http_upstream_zone_module.c
objs/ngx_modules.c

src/event/ngx_event.c
src/event/ngx_event_timer.c
src/event/ngx_event_posted.c
src/event/ngx_event_accept.c
src/event/ngx_event_udp.c
src/event/ngx_event_connect.c
src/event/ngx_event_pipe.c
"
#  src/http/modules/ngx_http_gzip_filter_module.c

CPP_EXTRA_ARGS="-includeframa-include/__fc_stubs.h -I frama-include -I src/core -I src/event -I src/event/modules -I src/os/unix -I objs -I src/http -I src/http/modules -DNGX_HAVE_GMTOFF=0 -DNGX_HAVE_O_PATH=0 -DNGX_ZLIB=0 -DNGX_HAVE_TCP_INFO=0 -DNGX_HAVE_MEMALIGN=0 -DNGX_HAVE_POSIX_MEMALIGN=0 -DNGX_HAVE_IP_PKTINFO=0 -DNGX_HAVE_GNU_CRYPT_R=0 -DNGX_HAVE_EPOLL=0 -DNGX_HAVE_EPOLLEXCLUSIVE=0 -DNGX_HAVE_ACCEPT4=0"

# Improves analysis time, at the cost of extra memory usage
# https://github.com/Frama-C/Frama-C-snapshot/blob/9e6952e6b24e3d56ca1f922d5b87d2700432eb98/src/libraries/utils/binary_cache.ml#L23-L40
export FRAMA_C_MEMORY_FOOTPRINT=10


# -machdep=x86_64

# Parsing
frama-c -metrics -cpp-extra-args="$CPP_EXTRA_ARGS" \
        -kernel-warn-key annot:missing-spec=abort \
        -kernel-warn-key typing:implicit-function-declaration=abort \
        -save=$OUTPATH/parsed.sav $FILES | tee $OUTPATH/parse.log

#
# Option -eva-precision allows setting a global trade-off between precision and analysis time.
# By default, Eva is tuned to a low precision to ensure a fast initial analysis. Especially for
# smaller code bases, it is often useful to increase this precision, to dismiss “easy” alarms.
# Precision can be set between 0 and 11, the higher the value, the more precise the analysis.
# The default value of Eva is somewhere between 0 and 1, so that setting -eva-precision 0
# potentially allows it to go even faster (only useful for large or very complex code bases).
#
# -eva-precision is in fact a meta-option, whose only purpose is to set the values of other
# options to a set of predefined values. This avoids the user having to know all of them, and
# which values are reasonable. Think of it as a “knob” to perform a coarse adjustment of the

# -deps
# Functional dependencies list, for each output
# location, the input locations that influence the final contents of this output location:

# -main
# select entrypoint function

# -lib-entry
# smaller entrypoint subset


# analysis, before fine-tuning it more precisely with other options.
frama-c -load $OUTPATH/parsed.sav \
        -main main \
        -eva \
        -eva-ignore-recursive-calls \
        -eva-use-spec=ngx_log_error_core \
        -eva-warn-key builtins:missing-spec=abort \
        -eva-warn-key alarm=inactive \
        -save=$OUTPATH/analyzed.sav | tee $OUTPATH/analyze.log

# -eva-warn-key garbled-mix=abort \
