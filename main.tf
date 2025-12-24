locals {
  name = "set-26"
  db_cred = jsondecode(aws_secretsmanager_secret_version.db_cred_version.secret_string)
  s3_origin_id = aws_s3_bucket.media-bucket.id
}
resource "tls_private_key" "key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}
 
resource "local_file" "key" {
  content         = tls_private_key.key.private_key_pem
  filename        = "set26-key"
  file_permission = "600"
}
resource "aws_key_pair" "key" {
  key_name   = "set26-pub-key"
  public_key = tls_private_key.key.public_key_openssh
}
 

# this block creat the Vpc
resource "aws_vpc" "vpc" {
  cidr_block = "10.0.0.0/16"

tags = {
    Name = "${var.name}-vpc"
  }
}

# this bloock is for public subnet
resource "aws_subnet" "pub_sub1" {
 vpc_id     = aws_vpc.vpc.id
 cidr_block = "10.0.3.0/24" 
 availability_zone = "eu-west-3a"

tags = {
    Name = "${var.name}-pub-sub1"
  }
}

resource "aws_subnet" "pub_sub2" {
  vpc_id     = aws_vpc.vpc.id
  cidr_block = "10.0.4.0/24"
  availability_zone = "eu-west-3b"

tags = {
    Name = "${var.name}-pub-sub2"
  }
}

# this block creates a private subnet
resource "aws_subnet" "pri_sub1" {
  vpc_id     = aws_vpc.vpc.id
  cidr_block = "10.0.1.0/24"
  availability_zone = "eu-west-3a"

tags = {
    Name = "${var.name}-pri-sub1"
  }
}

resource "aws_subnet" "pri_sub2" {
  vpc_id     = aws_vpc.vpc.id
  cidr_block = "10.0.2.0/24"
  availability_zone = "eu-west-3b"

tags = {
    Name = "${var.name}-pri-sub2"
  }
}

# this block creates a internet gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id

tags = {
    Name = "${var.name}-igw"
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
    Name = "${var.name}-nat"
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
    Name = "${var.name}-pub-rt"
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
    Name = "${var.name}-pri-rt"
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

# create security group for web application server
resource "aws_security_group" "frontend_sg" {
  name = "frontend_sg"
  description = "this bloock creates a security group"
  vpc_id      = aws_vpc.vpc.id

  
  ingress {
    description = "this is to allow SSH access"
    protocol    = "tcp"
    self        = true
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "this is to allow HTTP-port"
    protocol    = "tcp"
    self        = true
    from_port   = 80
    to_port     = 80
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "${local.name}-frontend_sg"
  }
}

# create security group for backend database application server
resource "aws_security_group" "backend_sg" {
  name = "backend_sg"
  description = "this allow traffic from frontend "
  vpc_id      = aws_vpc.vpc.id

  
  ingress {
    description = "this is to allow SSH access from frontend"
    protocol    = "tcp"
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "Allow MYSQL/AURORA from frontend SG"
    protocol    = "tcp"
    from_port   = 3306
    to_port     = 3306
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "${local.name}-backend_sg"
  }
}

