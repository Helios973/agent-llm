FROM nginx:alpine

COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY frontend /usr/share/nginx/html
COPY docker/runtime-config.js /usr/share/nginx/html/assets/runtime-config.js

EXPOSE 80
