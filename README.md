
<p align="center"><strong><a href="https://hostvn.net">Hostvn.net - Tên miền, Web Hosting, Email, VPS &amp; Dịch vụ lưu trữ Website</a></strong></p>
<p align="center"> <img src="https://blog.hostvn.net/wp-content/uploads/2020/07/logo-big-2.png" /> </p>

########################################################################################

## About Hostvn.net Nginx

Hostvn.net Nginx is developed based on the Nginx Docker official, not only inherits the advantages of Nginx Docker official but also helps to customize the configuration and add some modules.

<h2>Quick reference</h2>

- Maintained by: <a href="https://hostvn.net">Hostvn.net</a>
- Github:
- Nginx Official: https://hub.docker.com/_/nginx
- Nginx Brotli module: https://github.com/google/ngx_brotli
- Nginx header more module: https://github.com/openresty/headers-more-nginx-module

<h2>Changes:</h2>

- Customize <b>/etc/nginx/nginx.conf</b> file configuration more optimally
- Add module ngx_brotli
- Add module ngx_headers_more
- Add the security configuration file at: <b>/etc/nginx/security.conf</b>
- Add the configuration file CloudFlare ip: <b>/etc/nginx/cloudflare.conf</b>
- Added security header structure

<h2>Using:</h2>

<code>docker run --name nginx -p 80:80 -p 443:443 -v ${PWD}/web:/usr/share/nginx/html --restart always -d hostvn/hostvn.net-nginx</code>

Also you can refer to how to use here: https://hub.docker.com/_/nginx
