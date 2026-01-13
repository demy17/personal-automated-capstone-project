variable "name" {
  description = "Project name prefix"
  type        = string
  default     = "set-26"
}

variable "dbcred1" {
    type = map(string)
    default = {
      username = "admin"
      password = "admin123"
    }
}

variable "ami_id" {
  description = "Amazon Linux 2 AMI for WordPress EC2 instances"
  type        = string
  default     = "ami-0c02fb55956c7d316"
}

variable "instance_type" {
  description = "EC2 instance type for WordPress"
  type        = string
  default     = "t3.micro"

}
variable "db_endpoint" {
  description = "RDS endpoint without port"
  type        = string
}
variable "db_name" {
  description = "WordPress database name"
  type        = string
}

variable "db_username" {
  description = "WordPress database username"
  type        = string
  sensitive   = true
}

variable "db_password" {
  description = "WordPress database password"
  type        = string
  sensitive   = true
}