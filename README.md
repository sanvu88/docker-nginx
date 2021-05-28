
<p align="center"><strong><a href="https://hostvn.net">Hostvn.net - Tên miền, Web Hosting, Email, VPS &amp; Dịch vụ lưu trữ Website</a></strong></p>
<p align="center"> <img src="https://blog.hostvn.net/wp-content/uploads/2020/07/logo-big-2.png" /> </p>

#####################################################################################

## About Hostvn.net Nginx

Hostvn.net Nginx is developed based on the Nginx Docker official, not only inherits the advantages of Nginx Docker official but also helps to customize the configuration and add some modules.

## Quick reference

- Maintained by: <a href="https://hostvn.net">Hostvn.net</a>
- Docker hub: https://hub.docker.com/r/hostvn/hostvn.net-nginx
- Nginx Official: https://hub.docker.com/_/nginx
- Nginx Brotli module: https://github.com/google/ngx_brotli
- Nginx header more module: https://github.com/openresty/headers-more-nginx-module

## Supported tags

- latest, 1.20.0, 1.20.1, 1.21.0

## Changes:

- Customize <b>/etc/nginx/nginx.conf</b> file configuration more optimally
- Add module ngx_brotli
- Add module ngx_headers_more
- Add the security configuration file at: <b>/etc/nginx/extra/security.conf</b>
- Block Exploits, SQL Injections, File Injections, Spam, User Agents, Etc configuration file at:
  <b>/etc/nginx/extra/block.conf</b>
- Add the configuration file CloudFlare ip: <b>/etc/nginx/cloudflare.conf</b>
- Added security header structure

## Using:

```html
docker pull hostvn/hostvn.net-nginx
```

```html
docker run --name nginx -p 80:80 -p 443:443 --restart always -v ${PWD}/web:/usr/share/nginx/html -d hostvn/hostvn.net-nginx
```

Also you can refer to how to use here: https://hub.docker.com/_/nginx

```html
server {
    listen 80;
    error_log /home/web/logs/error.log;
    server_name example.org www.example.org;
    root /var/www/html;
    index index.php index.html index.htm;
    location / {
        try_files $uri $uri/ /index.php?$args;
    }

    location ~ \.php {
        try_files $uri =404;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_index index.php;
        include /etc/nginx/fastcgi_params;
        include /etc/nginx/nginx_limits.conf;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        if (-f $request_filename) {
            fastcgi_pass php:9000;
        }
    }

    include /etc/nginx/extra/security.conf;
}
```
