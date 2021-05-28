#!/bin/sh

#docker run --name nginx -p 80:80 -p 443:443 --restart always -d hostvn.net/nginx:1.20.0

# nano /etc/docker/daemon.json

#{
#    "insecure-registries": ["54.255.151.8:5000"]
#}

#docker pull 54.255.151.8:5000/hostvn.net/nginx:1.20.0
#docker run --name nginx -p 80:80 -p 443:443 --restart always -d 54.255.151.8:5000/hostvn.net/nginx:1.20.0

set -e

#IPADDRESS=$(curl -s http://cyberpanel.sh/?ip)
CPU_CORES=$(grep -c "processor" /proc/cpuinfo)
MAX_CLIENT=$((CPU_CORES * 1024))

NGINX_SERVICE_FILE="/lib/systemd/system/nginx.service"
NGINX_CONFIG_FILE="/etc/nginx/nginx.conf"
SELF_SIGNED_DIR="/etc/nginx/certs"

if [ -f $NGINX_SERVICE_FILE ]; then
    rm -rf $NGINX_SERVICE_FILE
fi

cat > "$NGINX_SERVICE_FILE" << END
[Unit]
Description=nginx - high performance web server
Documentation=https://nginx.org/en/docs/
After=network-online.target remote-fs.target nss-lookup.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/var/run/nginx.pid
ExecStart=/usr/sbin/nginx -c $NGINX_CONFIG_FILE
ExecReload=/bin/sh -c "/bin/kill -s HUP \$(/bin/cat /var/run/nginx.pid)"
ExecStop=/bin/sh -c "/bin/kill -s TERM \$(/bin/cat /var/run/nginx.pid)"
PrivateTmp=true
LimitMEMLOCK=infinity
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
END

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

#worker_connections=$(grep -w "worker_connections" $NGINX_CONFIG_FILE)

cat > "$NGINX_CONFIG_FILE" << END
user nginx;
worker_processes auto;
worker_rlimit_nofile 260000;

error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;

load_module /etc/nginx/modules/ngx_http_brotli_filter_module.so;
load_module /etc/nginx/modules/ngx_http_brotli_static_module.so;
load_module /etc/nginx/modules/ngx_http_headers_more_filter_module.so;

events {
    worker_connections $MAX_CLIENT;
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

cat >"/etc/nginx/nginx_limits.conf" <<EOCF
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

mkdir -p "$SELF_SIGNED_DIR"

if [ -f /etc/nginx/certs/dhparams.pem ]; then
    rm -rf /etc/nginx/certs/dhparams.pem
fi

if [ -d "$SELF_SIGNED_DIR}" ]; then
    openssl dhparam -out "$SELF_SIGNED_DIR"/dhparams.pem 2048
#    openssl genrsa -out "$SELF_SIGNED_DIR/server.key" 4096
#    openssl req -new -key "$SELF_SIGNED_DIR/server.key" \
#        -out "$SELF_SIGNED_DIR/server.csr" -subj "/C=VN/ST=Caugiay/L=Hanoi/O=Hostvn/OU=IT Department/CN=${IPADDRESS}"  > /dev/null
#    openssl x509 -in "$SELF_SIGNED_DIR/server.csr" -out "$SELF_SIGNED_DIR/server.crt" \
#        -req -signkey "$SELF_SIGNED_DIR/server.key" -days 3650
fi

mkdir -p /etc/nginx/extra

cat >"/etc/nginx/extra/security.conf" <<EOsecurity
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
#server {
#    listen       443 ssl http2;
#    listen  [::]:443 ssl http2;
#    server_name  localhost;
#    location / {
#        root   /usr/share/nginx/html;
#        index  index.html index.htm;
#    }
#
#    ssl_certificate         $SELF_SIGNED_DIR/server.crt;
#    ssl_certificate_key     $SELF_SIGNED_DIR/server.key;
#
#    error_page   500 502 503 504  /50x.html;
#    location = /50x.html {
#        root   /usr/share/nginx/html;
#    }
#}
END

exit 0
