locals {
  wordpress_script = <<-EOF
#!/bin/bash
yum update -y

# Install required packages
yum install -y httpd php php-mysqlnd mod_ssl wget unzip

systemctl start httpd
systemctl enable httpd

cd /var/www/html

# Download WordPress
wget https://wordpress.org/latest.tar.gz
tar -xzf latest.tar.gz
cp -r wordpress/* .
rm -rf wordpress latest.tar.gz

chown -R apache:apache /var/www/html
chmod -R 755 /var/www/html

# Configure wp-config.php
cp wp-config-sample.php wp-config.php

sed -i "s/database_name_here/${var.db_name}/" wp-config.php
sed -i "s/username_here/${var.db_username}/" wp-config.php
sed -i "s/password_here/${var.db_password}/" wp-config.php
sed -i "s/localhost/${var.db_endpoint}/" wp-config.php

# Apache config
sed -i 's/AllowOverride None/AllowOverride All/' /etc/httpd/conf/httpd.conf

# Sync code from S3
aws s3 sync s3://${aws_s3_bucket.code_bucket.bucket} /var/www/html

# Cron jobs
echo "* * * * * ec2-user aws s3 sync s3://${aws_s3_bucket.code_bucket.bucket} /var/www/html" >> /etc/crontab
echo "* * * * * ec2-user aws s3 sync /var/www/html/wp-content/uploads/ s3://${aws_s3_bucket.media_bucket.bucket}" >> /etc/crontab

# Disable SELinux (lab-friendly)
setenforce 0
sed -i 's/^SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config

hostnamectl set-hostname wordpress-server
EOF
}
