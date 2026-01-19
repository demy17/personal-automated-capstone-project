locals {
  name = "set-26"
  db_cred = jsondecode(aws_secretsmanager_secret_version.db_cred_version.secret_string)
  s3_origin_id = aws_s3_bucket.media-bucket.id
}

# NETWORKING BLOCk (PHASE 1)

# this block creat the Vpc
resource "aws_vpc" "vpc" {
  cidr_block = "10.0.0.0/16"

tags = {
    Name = "${local.name}-vpc"
  }
}

# this bloock is for public subnet
resource "aws_subnet" "pub_sub1" {
 vpc_id     = aws_vpc.vpc.id
 cidr_block = "10.0.3.0/24" 
 availability_zone = "eu-west-3a"

tags = {
    Name = "${local.name}-pub-sub1"
  }
}

resource "aws_subnet" "pub_sub2" {
  vpc_id     = aws_vpc.vpc.id
  cidr_block = "10.0.4.0/24"
  availability_zone = "eu-west-3b"

tags = {
    Name = "${local.name}-pub-sub2"
  }
}

# this block creates a private subnet
resource "aws_subnet" "pri_sub1" {
  vpc_id     = aws_vpc.vpc.id
  cidr_block = "10.0.1.0/24"
  availability_zone = "eu-west-3a"

tags = {
    Name = "${local.name}-pri-sub1"
  }
}

resource "aws_subnet" "pri_sub2" {
  vpc_id     = aws_vpc.vpc.id
  cidr_block = "10.0.2.0/24"
  availability_zone = "eu-west-3b"

tags = {
    Name = "${local.name}-pri-sub2"
  }
}

# this block creates a internet gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id

tags = {
    Name = "${local.name}-igw"
  }
}
# this blolck creates a EPI(elastic ip) for nat gateway
resource "aws_eip" "eip" {
  domain = "vpc"
}
# this block creates a nat gateway
resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.eip.id
  subnet_id     = aws_subnet.pub_sub1.id
  depends_on    = [aws_internet_gateway.igw]
  tags = {
    Name = "${local.name}-nat"
  }
}


# this block creates a public route table
resource "aws_route_table" "pub_rt" {
  vpc_id = aws_vpc.vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = {
    Name = "${local.name}-pub-rt"
  }
}
# this bloock creates a route table assp. for public route
resource "aws_route_table_association" "pub_rt_asso" {
  subnet_id      = aws_subnet.pub_sub1.id
  route_table_id = aws_route_table.pub_rt.id
}
resource "aws_route_table_association" "pub_sub2" {
  subnet_id      = aws_subnet.pub_sub2.id
  route_table_id = aws_route_table.pub_rt.id
}

# this block creates a private route table
resource "aws_route_table" "pri_rt" {
  vpc_id = aws_vpc.vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_nat_gateway.nat.id
  }
  tags = {
    Name = "${local.name}-pri-rt"
  }
}
# this bloock creates a route table assp. for private route
resource "aws_route_table_association" "pri_rt_asso" {
  subnet_id      = aws_subnet.pri_sub1.id
  route_table_id = aws_route_table.pri_rt.id
}
resource "aws_route_table_association" "pri_rt_asso" {
  subnet_id      = aws_subnet.pri_sub2.id
  route_table_id = aws_route_table.pri_rt.id
}

# SECURITY BLOCK AND IDENTITY (PHASE 2)

# Define an Application Load Balancer
resource "aws_lb" "my_alb" {
  name               = "my-web-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = [aws_subnet.pub-sub1.id, aws_subnet.pub-sub2.id]

  tags = {
    Name = "${local.name}-my_alb"
  }
}
#  ALB Security Group (PUBLIC)
resource "aws_security_group" "alb_sg" {
  name   = "alb-sg"
  vpc_id = aws_vpc.vpc.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${local.name}-alb-sg"
  }
}
# EC2 / WordPress Security Group (PRIVATE)
resource "aws_security_group" "ec2_sg" {
  name   = "ec2-sg"
  vpc_id = aws_vpc.vpc.id

  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${local.name}-ec2-sg"
  }
}
# RDS / MySQL Security Group (PRIVATE)
resource "aws_security_group" "rds_sg" {
  name   = "rds-sg"
  vpc_id = aws_vpc.vpc.id

  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.ec2_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${local.name}-rds-sg"
  }
}

# Define an IAM Role for EC2
resource "aws_iam_role" "ec2_role" {
  name = "${local.name}-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "${local.name}-ec2-role"
  }
}

# SECRETS AND CONFIGURAATION  (PHASE 3)

# Custom IAM Policy (S3 + Secrets Manager)
resource "aws_iam_policy" "ec2_policy" {
  name = "${local.name}-ec2-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [

      # S3 Media Bucket access
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.media_bucket.arn,
          "${aws_s3_bucket.media_bucket.arn}/*"
        ]
      },

      # Secrets Manager
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = aws_secretsmanager_secret.db_credentials.arn
      }
    ]
  })
}

# Attach Custom Policy to Role
resource "aws_iam_role_policy_attachment" "custom_policy_attach" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.ec2_policy.arn
}
# Attach AWS Managed CloudWatch Policy
resource "aws_iam_role_policy_attachment" "cloudwatch_attach" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}
# IAM Instance Profile (USED BY LAUNCH TEMPLATE)
resource "aws_iam_instance_profile" "ec2_profile" {
  name = "${local.name}-ec2-profile"
  role = aws_iam_role.ec2_role.name
}

# secret manger block 
resource "aws_secretsmanager_secret" "db_credentials" {
  name = "${local.name}-db-credentials"
  description = "Database credentials for WordPress RDS"

  tags = {
    Name = "${local.name}-db-secret"
  }
}
# Create the Secret Version (Actual credentials)
resource "aws_secretsmanager_secret_version" "db_credentials_version" {
  secret_id = aws_secretsmanager_secret.db_credentials.id

  secret_string =jsonencode(var.dbcred1)
}

# STORAGE LAYER (PHASE 4)

# create media bucktet
resource "aws_s3_bucket" "media_bucket" {
  bucket        = "${local.name}-media-bucket1"
  force_destroy = true
  #depends_on    = [null_resource.pre_scan]
  tags = {
    Name = "${local.name}-media-bucket"
  }
}
resource "aws_s3_bucket_public_access_block" "media_pub" {
  bucket                  = aws_s3_bucket.media_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_ownership_controls" "media_ctrl" {
  bucket = aws_s3_bucket.media_bucket.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
  depends_on = [aws_s3_bucket_public_access_block.media_pub]
 
}
# S3 code Bucket
resource "aws_s3_bucket" "code_bucket" {
  bucket        = "${local.name}-code-bucket"
  #depends_on    = [null_resource.pre_scan]
  force_destroy = true
 
  tags = {
    Name = "${local.name}-code-bucket"
  }
}
resource "aws_s3_bucket_public_access_block" "code_block" {
  bucket                  = aws_s3_bucket.code_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
# Creating log bucket
resource "aws_s3_bucket" "log_bucket" {
  bucket        = "${local.name}-log-bucket"
  force_destroy = true
  #depends_on    = [null_resource.pre_scan]
 
  tags = {
    Name = "${local.name}-log-bucket"
  }
}
# Setting bucket ownership controls
resource "aws_s3_bucket_ownership_controls" "log_owner" {
  bucket = aws_s3_bucket.log_bucket.id
 
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}
# Public access block (still PRIVATE)
 resource "aws_s3_bucket_public_access_block" "log_block" {
  bucket                  = aws_s3_bucket.log_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
# Creating log bucket policy
data "aws_iam_policy_document" "log_bucket_policy" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.log_bucket.arn}/*"]
  }
}
resource "aws_s3_bucket_policy" "log_policy" {
  bucket = aws_s3_bucket.log_bucket.id
  policy = data.aws_iam_policy_document.log_bucket_policy.json
}

#  DATABASED LAYER (PHASE 5)

# Create DB subnet group
resource "aws_db_subnet_group" "db_subnet_group" {
  name       = "${local.name}-db-subnet-group"
  description = "Subnet group for RDS database"
  subnet_ids = [
    aws_subnet.pri_sub1.id,
    aws_subnet.pri-sub2.id
  ]

  tags = {
    Name = "${local.name}-db-subnet-group"
  }
}
# Create the RDS Database
resource "aws_db_instance" "wordpress_db" {
  identifier        = "${local.name}-wordpress-db"
  engine            = "mysql"
  engine_version    = "8.0"
  instance_class    = "db.t3.micro"       
  allocated_storage = 20                  
  db_name           = "wordpress"       
  username = jsondecode(
    aws_secretsmanager_secret_version.db_credentials_version.secret_string
  )["username"]
  password = jsondecode(
    aws_secretsmanager_secret_version.db_credentials_version.secret_string
  )["password"]
  port = 3306

  db_subnet_group_name   = aws_db_subnet_group.db_subnet_group.name
  vpc_security_group_ids = [aws_security_group.rds_sg.id]  # Allow access from app servers
  backup_retention_period = 3
  backup_window = "03:00-04:00"
  deletion_protection = false 
  multi_az            = false             
  publicly_accessible = false            
  skip_final_snapshot = true              

  tags = {
    Name = "${local.name}-rds-db"
  }
}

#COMPUTE LAYER (PHASE 6)
# SSH Key Pair
resource "aws_key_pair" "key" {
  key_name   = "${local.name}-key"
  public_key = file("./set-26-key.pub")

 tags = {
    Name = "${local.name}-key"
  }
}
 
# Launch Template for WordPress EC2 instances
resource "aws_launch_template" "launch_template" {
  name_prefix   = "${local.name}-web-lt-"
  image_id      = var.ami_id
  instance_type = var.instance_type
  key_name      = aws_key_pair.key.key_name

  network_interfaces {
    associate_public_ip_address = false
    security_groups = [aws_security_group.ec2_sg.id]
  }

  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_profile.name
  }

  user_data = base64encode(local.wordpress_script)

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "${local.name}-wordpress"
    }
  }
}

# Create the Auto Scaling Group
resource "aws_autoscaling_group" "my_asg" {
  name                = "${local.name}-web-asg"
  vpc_zone_identifier = [aws_subnet.pri_sub1.id,aws_subnet.pri_sub2.id]
  desired_capacity = 2
  min_size         = 1
  max_size         = 4

  health_check_type         = "ELB"
  health_check_grace_period = 300
  force_delete              = true

  launch_template {
    id      = aws_launch_template.launch_template.id
    version = "$Latest"
  }
  target_group_arns = [aws_lb_target_group.my_target_group.arn]

  tag {
    key                 = "Name"
    value               = "${local.name}-wordpress"
    propagate_at_launch = true
  }
}

# auto scaling policy
resource "aws_autoscaling_policy" "scale_out" {
  name                   = "${local.name}-scale-out"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.my_asg.name
}

# Phase 7 (Traffic management)
# HTTP Target Group
resource "aws_lb_target_group" "wordpress_tg" {
  name        = "${local.name}-tg"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = aws_vpc.vpc.id
  target_type = "instance"

  health_check {
    path                = "/indextest.html"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 3
    unhealthy_threshold = 3
    matcher             = "200"
  }

  tags = {
    Name = "${local.name}-tg"
  }
}
#creating acm certificate for ssl
resource "aws_acm_certificate" "acm_cert" {
  domain_name               = "aleyi.space"
  validation_method         = "DNS"
  lifecycle {
    create_before_destroy = true
  }
}
# Route53 Validation Records
resource "aws_route53_record" "cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.acm_cert.domain_validation_options :
    dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  zone_id = data.aws_route53_zone.set_26_hz.zone_id
  name    = each.value.name
  type    = each.value.type
  records = [each.value.record]
  ttl     = 60
}
# Certificate Validation
resource "aws_acm_certificate_validation" "cert_validation" {
  certificate_arn         = aws_acm_certificate.acm_cert.arn
  validation_record_fqdns = [
    for record in aws_route53_record.cert_validation : record.fqdn
  ]
}
# HTTP Listener → HTTPS Redirect
resource "aws_lb_listener" "http_listener" {
  load_balancer_arn = aws_lb.my_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}
# HTTPS Listener → Target Group
resource "aws_lb_listener" "https_listener" {
  load_balancer_arn = aws_lb.my_alb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = aws_acm_certificate_validation.cert_validation.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.wordpress_tg.arn
  }
}
# Phase 8 (CDN & Performance)
#  CloudFront Origin Access Control (OAC)
resource "aws_cloudfront_origin_access_control" "set_26_media_oac" {
  name                              = "${local.name}-media-oac"
  description                       = "OAC for ${local.name}-media-bucket"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}
#  CloudFront Distribution
resource "aws_cloudfront_distribution" "set_26_media_distribution" {
  enabled = true

  origin {
    domain_name              = aws_s3_bucket.media_bucket.bucket_regional_domain_name
    origin_id                = local.s3_origin_id
    origin_access_control_id = aws_cloudfront_origin_access_control.set_26_media_oac.id
  }

  default_cache_behavior {
    target_origin_id       = local.s3_origin_id
    viewer_protocol_policy = "redirect-to-https"

    allowed_methods = ["GET", "HEAD"]
    cached_methods  = ["GET", "HEAD"]

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
    min_ttl     = 3600
    default_ttl = 86400
    max_ttl     = 31536000
  }
  price_class = "PriceClass_100"
  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
  viewer_certificate {
  acm_certificate_arn      = aws_acm_certificate.us_east_cert.arn
  ssl_support_method       = "sni-only"
  minimum_protocol_version = "TLSv1.2_2021"
}
  tags = {
    Name = "${local.name}-media-distribution"
  }
}
# S3 Media Bucket Policy
data "aws_iam_policy_document" "media_bucket_policy" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.media_bucket.arn}/*"]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.set_26_media_distribution.arn]
    }
  }
}
resource "aws_s3_bucket_policy" "media_bucket_policy" {
  bucket = aws_s3_bucket.media_bucket.id
  policy = data.aws_iam_policy_document.media_bucket_policy.json
}
