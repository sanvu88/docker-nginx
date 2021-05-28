#!/bin/sh
# vim:sw=2:ts=2:sts=2:et

set -eu

LC_ALL=C
ME=$( basename "$0" )
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
IPADDRESS=$(curl -s http://cyberpanel.sh/?ip)

[ "${NGINX_ENTRYPOINT_WORKER_PROCESSES_AUTOTUNE:-}" ] || exit 0

touch /etc/nginx/nginx.conf 2>/dev/null || { echo >&2 "$ME: error: can not modify /etc/nginx/nginx.conf (read-only file system?)"; exit 0; }

ceildiv() {
  num=$1
  div=$2
  echo $(( (num + div - 1) / div ))
}

get_cpuset() {
  cpusetroot=$1
  cpusetfile=$2
  ncpu=0
  [ -f "$cpusetroot/$cpusetfile" ] || return 1
  for token in $( tr ',' ' ' < "$cpusetroot/$cpusetfile" ); do
    case "$token" in
      *-*)
        count=$( seq $(echo "$token" | tr '-' ' ') | wc -l )
        ncpu=$(( ncpu+count ))
        ;;
      *)
        ncpu=$(( ncpu+1 ))
        ;;
    esac
  done
  echo "$ncpu"
}

get_quota() {
  cpuroot=$1
  ncpu=0
  [ -f "$cpuroot/cpu.cfs_quota_us" ] || return 1
  [ -f "$cpuroot/cpu.cfs_period_us" ] || return 1
  cfs_quota=$( cat "$cpuroot/cpu.cfs_quota_us" )
  cfs_period=$( cat "$cpuroot/cpu.cfs_period_us" )
  [ "$cfs_quota" = "-1" ] && return 1
  [ "$cfs_period" = "0" ] && return 1
  ncpu=$( ceildiv "$cfs_quota" "$cfs_period" )
  [ "$ncpu" -gt 0 ] || return 1
  echo "$ncpu"
}

get_quota_v2() {
  cpuroot=$1
  ncpu=0
  [ -f "$cpuroot/cpu.max" ] || return 1
  cfs_quota=$( cut -d' ' -f 1 < "$cpuroot/cpu.max" )
  cfs_period=$( cut -d' ' -f 2 < "$cpuroot/cpu.max" )
  [ "$cfs_quota" = "max" ] && return 1
  [ "$cfs_period" = "0" ] && return 1
  ncpu=$( ceildiv "$cfs_quota" "$cfs_period" )
  [ "$ncpu" -gt 0 ] || return 1
  echo "$ncpu"
}

get_cgroup_v1_path() {
  needle=$1
  found=
  foundroot=
  mountpoint=

  [ -r "/proc/self/mountinfo" ] || return 1
  [ -r "/proc/self/cgroup" ] || return 1

  while IFS= read -r line; do
    case "$needle" in
      "cpuset")
        case "$line" in
          *cpuset*)
            found=$( echo "$line" | cut -d ' ' -f 4,5 )
            break
            ;;
        esac
        ;;
      "cpu")
        case "$line" in
          *cpuset*)
            ;;
          *cpu,cpuacct*|*cpuacct,cpu|*cpuacct*|*cpu*)
            found=$( echo "$line" | cut -d ' ' -f 4,5 )
            break
            ;;
        esac
    esac
  done << __EOF__
$( grep -F -- '- cgroup ' /proc/self/mountinfo )
__EOF__

  while IFS= read -r line; do
    controller=$( echo "$line" | cut -d: -f 2 )
    case "$needle" in
      "cpuset")
        case "$controller" in
          cpuset)
            mountpoint=$( echo "$line" | cut -d: -f 3 )
            break
            ;;
        esac
        ;;
      "cpu")
        case "$controller" in
          cpu,cpuacct|cpuacct,cpu|cpuacct|cpu)
            mountpoint=$( echo "$line" | cut -d: -f 3 )
            break
            ;;
        esac
        ;;
    esac
done << __EOF__
$( grep -F -- 'cpu' /proc/self/cgroup )
__EOF__

  case "${found%% *}" in
    "/")
      foundroot="${found##* }$mountpoint"
      ;;
    "$mountpoint")
      foundroot="${found##* }"
      ;;
  esac
  echo "$foundroot"
}

get_cgroup_v2_path() {
  found=
  foundroot=
  mountpoint=

  [ -r "/proc/self/mountinfo" ] || return 1
  [ -r "/proc/self/cgroup" ] || return 1

  while IFS= read -r line; do
    found=$( echo "$line" | cut -d ' ' -f 4,5 )
  done << __EOF__
$( grep -F -- '- cgroup2 ' /proc/self/mountinfo )
__EOF__

  while IFS= read -r line; do
    mountpoint=$( echo "$line" | cut -d: -f 3 )
done << __EOF__
$( grep -F -- '0::' /proc/self/cgroup )
__EOF__

  case "${found%% *}" in
    "")
      return 1
      ;;
    "/")
      foundroot="${found##* }$mountpoint"
      ;;
    "$mountpoint")
      foundroot="${found##* }"
      ;;
  esac
  echo "$foundroot"
}

ncpu_online=$( getconf _NPROCESSORS_ONLN )
ncpu_cpuset=
ncpu_quota=
ncpu_cpuset_v2=
ncpu_quota_v2=

cpuset=$( get_cgroup_v1_path "cpuset" ) && ncpu_cpuset=$( get_cpuset "$cpuset" "cpuset.effective_cpus" ) || ncpu_cpuset=$ncpu_online
cpu=$( get_cgroup_v1_path "cpu" ) && ncpu_quota=$( get_quota "$cpu" ) || ncpu_quota=$ncpu_online
cgroup_v2=$( get_cgroup_v2_path ) && ncpu_cpuset_v2=$( get_cpuset "$cgroup_v2" "cpuset.cpus.effective" ) || ncpu_cpuset_v2=$ncpu_online
cgroup_v2=$( get_cgroup_v2_path ) && ncpu_quota_v2=$( get_quota_v2 "$cgroup_v2" ) || ncpu_quota_v2=$ncpu_online

ncpu=$( printf "%s\n%s\n%s\n%s\n%s\n" \
               "$ncpu_online" \
               "$ncpu_cpuset" \
               "$ncpu_quota" \
               "$ncpu_cpuset_v2" \
               "$ncpu_quota_v2" \
               | sort -n \
               | head -n 1 )


if [ ! -d /etc/nginx ]; then
    mkdir -p etc/nginx
fi

if [ ! -d /etc/nginx/modules ]; then
    mkdir -p /etc/nginx/modules
fi

apt update -y
apt install --no-install-recommends --no-install-suggests wget -y

wget https://scripts.hostvn.net/ngx_brotli/1.20.0/ngx_http_brotli_filter_module.so -P /etc/nginx/modules
wget https://scripts.hostvn.net/ngx_brotli/1.20.0/ngx_http_brotli_static_module.so -P /etc/nginx/modules
wget https://scripts.hostvn.net/ngx_brotli/1.20.0/ngx_http_headers_more_filter_module.so -P /etc/nginx/modules

apt-get remove --purge --auto-remove -y

#worker_connections=$(grep -w "worker_connections" /etc/nginx/nginx.conf)

cat > "/etc/nginx/nginx.conf" << END
user nginx;
worker_processes auto;
worker_rlimit_nofile 260000;

error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;

load_module /etc/nginx/modules/ngx_http_brotli_filter_module.so;
load_module /etc/nginx/modules/ngx_http_brotli_static_module.so;
load_module /etc/nginx/modules/ngx_http_headers_more_filter_module.so;

events {
    worker_connections 512;
    accept_mutex off;
    accept_mutex_delay 200ms;
    use epoll;
    #multi_accept on;
}

http {
    index  index.html index.htm index.php;
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    charset utf-8;

    log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                  '\$status \$body_bytes_sent "\$http_referer" '
                  '"\$http_user_agent" "\$http_x_forwarded_for"';

    access_log  off;
    server_tokens off;

    sendfile on;

    tcp_nopush on;
    tcp_nodelay off;

    types_hash_max_size 2048;
    server_names_hash_bucket_size 128;
    server_names_hash_max_size 10240;
    client_max_body_size 1024m;
    client_body_buffer_size 128k;
    client_body_in_file_only off;
    client_body_timeout 60s;
    client_header_buffer_size 256k;
    client_header_timeout  20s;
    large_client_header_buffers 8 256k;
    keepalive_timeout 15;
    keepalive_disable msie6;
    reset_timedout_connection on;
    send_timeout 60s;

    disable_symlinks if_not_owner from=\$document_root;
    server_name_in_redirect off;

    open_file_cache max=2000 inactive=20s;
    open_file_cache_valid 120s;
    open_file_cache_min_uses 2;
    open_file_cache_errors off;

    # Limit Request
    limit_req_status 403;
    # limit the number of connections per single IP
    limit_conn_zone \$binary_remote_addr zone=conn_limit_per_ip:10m;
    # limit the number of requests for a given session
    limit_req_zone \$binary_remote_addr zone=req_limit_per_ip:10m rate=1r/s;

    # Custom Response Headers
    more_set_headers 'Server: HOSTVN.NET';
    more_set_headers 'X-Content-Type-Options    "nosniff" always';
    more_set_headers 'X-XSS-Protection          "1; mode=block" always';
    more_set_headers 'Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always';
    more_set_headers 'Referrer-Policy "no-referrer-when-downgrade" always'

    include /etc/nginx/gzip.conf;
    include /etc/nginx/brotli.conf;
    include /etc/nginx/ssl.conf;
    include /etc/nginx/cloudflare.conf;
    include /etc/nginx/conf.d/*.conf;
}
END

cat > "/etc/nginx/gzip.conf" << END
##Gzip Compression
gzip on;
gzip_static on;
gzip_disable msie6;
gzip_vary on;
gzip_proxied any;
gzip_comp_level 2;
gzip_buffers 16 8k;
gzip_http_version 1.1;
gzip_min_length 256;
gzip_types
    application/atom+xml
    application/geo+json
    application/javascript
    application/json
    application/ld+json
    application/manifest+json
    application/rdf+xml
    application/rss+xml
    application/vnd.ms-fontobject
    application/wasm
    application/x-font-opentype
    application/x-font-truetype
    application/x-font-ttf
    application/x-javascript
    application/x-web-app-manifest+json
    application/xhtml+xml
    application/xml
    application/xml+rss
    font/eot
    font/opentype
    font/otf
    image/bmp
    image/svg+xml
    image/vnd.microsoft.icon
    image/x-icon
    image/x-win-bitmap
    text/cache-manifest
    text/calendar
    text/css
    text/javascript
    text/markdown
    text/plain
    text/vcard
    text/vnd.rim.location.xloc
    text/vtt
    text/x-component
    text/x-cross-domain-policy
    text/xml;
END

cat > "/etc/nginx/brotli.conf" << END
##Brotli Compression
brotli on;
brotli_static on;
brotli_buffers 16 8k;
brotli_comp_level 5;
brotli_types
    application/atom+xml
    application/geo+json
    application/javascript
    application/json
    application/ld+json
    application/manifest+json
    application/rdf+xml
    application/rss+xml
    application/vnd.ms-fontobject
    application/wasm
    application/x-font-opentype
    application/x-font-truetype
    application/x-font-ttf
    application/x-javascript
    application/x-web-app-manifest+json
    application/xhtml+xml
    application/xml
    application/xml+rss
    font/eot
    font/opentype
    font/otf
    image/bmp
    image/svg+xml
    image/vnd.microsoft.icon
    image/x-icon
    image/x-win-bitmap
    text/cache-manifest
    text/calendar
    text/css
    text/javascript
    text/markdown
    text/plain
    text/vcard
    text/vnd.rim.location.xloc
    text/vtt
    text/x-component
    text/x-cross-domain-policy
    text/xml;
END

cat > "/etc/nginx/ssl.conf" << END
# SSL
ssl_session_timeout  1d;
ssl_session_cache    shared:SSL:300m;
ssl_session_tickets  off;

# Diffie-Hellman parameter for DHE ciphersuites
ssl_dhparam /etc/nginx/certs/dhparams.pem;

# Mozilla Intermediate configuration
ssl_protocols        TLSv1.2 TLSv1.3;
ssl_ciphers          ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

# OCSP Stapling
#ssl_stapling         on;
#ssl_stapling_verify  on;
resolver             1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 208.67.222.222 208.67.220.220 valid=10m;
resolver_timeout     10s;
END

cat >>"/etc/nginx/nginx_limits.conf" <<EOCF
fastcgi_connect_timeout 60;
fastcgi_buffer_size 128k;
fastcgi_buffers 256 16k;
fastcgi_busy_buffers_size 256k;
fastcgi_temp_file_write_size 256k;
fastcgi_send_timeout 600;
fastcgi_read_timeout 600;
fastcgi_intercept_errors on;
fastcgi_param HTTP_PROXY "";
EOCF

cat > "/etc/nginx/cloudflare.conf" <<END
real_ip_header X-Forwarded-For;
END

for ipv4 in `curl https://www.cloudflare.com/ips-v4` ; do
        cat >>"/etc/nginx/cloudflare.conf" <<EOcf_ipv4
set_real_ip_from $ipv4;
EOcf_ipv4
    done

    for ipv6 in `curl https://www.cloudflare.com/ips-v6` ; do
        cat >>"/etc/nginx/cloudflare.conf" <<EOcf_ipv6
set_real_ip_from $ipv6;
EOcf_ipv6
    done

self_signed_dir=/etc/nginx/certs
mkdir -p "${self_signed_dir}"

if [ -f /etc/nginx/certs/dhparams.pem ]; then
    rm -rf /etc/nginx/certs/dhparams.pem
fi

if [ -d "${self_signed_dir}" ]; then
    openssl dhparam -out "${self_signed_dir}"/dhparams.pem 2048
    openssl genrsa -out "${self_signed_dir}/server.key" 4096
    openssl req -new -key "${self_signed_dir}/server.key" \
        -out "${self_signed_dir}/server.csr" -subj "/C=VN/ST=Caugiay/L=Hanoi/O=Hostvn/OU=IT Department/CN=${IPADDRESS}"  > /dev/null
    openssl x509 -in "${self_signed_dir}/server.csr" -out "${self_signed_dir}/server.crt" \
        -req -signkey "${self_signed_dir}/server.key" -days 3650
fi

mkdir -p /etc/nginx/extra

cat >>"/etc/nginx/extra/security.conf" <<EOsecurity
location ^~ /GponForm/ { deny all; access_log off; log_not_found off; }
location ^~ /GponForm/diag_Form { deny all; access_log off; log_not_found off; }
location ^~ /vendor/phpunit/ { deny all; access_log off; log_not_found off; }
# Return 403 forbidden for readme.(txt|html) or license.(txt|html) or example.(txt|html) or other common git repository files
location ~*  "/(^\$|readme|license|example|LICENSE|README|LEGALNOTICE|INSTALLATION|CHANGELOG)\.(txt|html|md)" {
    deny all;
}
location ~ ^/(\.user.ini|\.htaccess|\.htpasswd|\.user\.ini|\.ht|\.env|\.git|\.svn|\.project) {
    deny all;
    access_log off;
    log_not_found off;
}
# Deny backup extensions & log files and return 403 forbidden
location ~* "\.(love|error|kid|cgi|old|orig|original|php#|php~|php_bak|save|swo|aspx?|tpl|sh|bash|bak?|cfg|cgi|dll|exe|git|hg|ini|jsp|log|mdb|out|sql|svn|swp|tar|rdf|gz|zip|bz2|7z|pem|asc|conf|dump)\$" {
    deny all;
    access_log off;
    log_not_found off;
}
# Disable XML-RPC
location = /xmlrpc.php { deny all; access_log off; log_not_found off; }
if (\$request_method !~ ^(GET|HEAD|POST)$ ) { return 405; }
rewrite /wp-admin$ \$scheme://\$host\$uri/ permanent;

location /wp-includes/{
    location ~ \.(gz|tar|bzip2|7z|php|php5|php7|log|error|py|pl|kid|love|cgi)\$ { deny all; }
}
location /wp-content/uploads {
    location ~ \.(gz|tar|bzip2|7z|php|php5|php7|log|error|py|pl|kid|love|cgi)\$ { deny all; }
}
location /wp-content/updraft { deny all; access_log off; log_not_found off; }
location /wp-content/backups-dup-pro { deny all; access_log off; log_not_found off; }
location /wp-snapshots { deny all; access_log off; log_not_found off; }
location /wp-content/uploads/sucuri { deny all; access_log off; log_not_found off; }
location /wp-content/uploads/nginx-helper { deny all; access_log off; log_not_found off; }
location = /wp-config.php { deny all; access_log off; log_not_found off; }
location = /wp-links-opml.php { deny all; access_log off; log_not_found off; }
location = /wp-config-sample.php { deny all; access_log off; log_not_found off; }
location = /readme.html { deny all; access_log off; log_not_found off; }
location = /license.txt { deny all; access_log off; log_not_found off; }

# enable gzip on static assets - php files are forbidden
location /wp-content/cache {
# Cache css & js files
    location ~* \.(?:css(\.map)?|js(\.map)?|.html)\$ {
        add_header Access-Control-Allow-Origin *;
        access_log off;
        log_not_found off;
        expires 365d;
    }
    location ~ \.php\$ { deny all; access_log off; log_not_found off; }
}
EOsecurity

cat > "/etc/nginx/conf.d/default.conf" << END
server {
    listen       80;
    listen  [::]:80;
    server_name  localhost;
    location / {
        root   /usr/share/nginx/html;
        index  index.html index.htm;
    }

    error_page   500 502 503 504  /50x.html;
    location = /50x.html {
        root   /usr/share/nginx/html;
    }
}
server {
    listen       443 ssl http2;
    listen  [::]:443 ssl http2;
    server_name  localhost;
    location / {
        root   /usr/share/nginx/html;
        index  index.html index.htm;
    }

    ssl_certificate         $self_signed_dir/server.crt;
    ssl_certificate_key     $self_signed_dir/server.key;

    error_page   500 502 503 504  /50x.html;
    location = /50x.html {
        root   /usr/share/nginx/html;
    }
}
END


sed -i.bak -r 's/^(worker_processes)(.*)$/# Commented out by '"$ME"' on '"$(date)"'\n#\1\2\n\1 '"$ncpu"';/' /etc/nginx/nginx.conf
