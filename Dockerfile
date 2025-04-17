# Use official PHP image with Apache
FROM php:8.1-apache

# Copy your project files into the container's web root
COPY . /var/www/html/

# Enable Apache rewrite module (optional)
RUN a2enmod rewrite

# Expose port 80 for HTTP
EXPOSE 80
