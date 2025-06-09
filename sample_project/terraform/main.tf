# Sample Terraform configuration for testing DevOps Buddy
# This contains intentional security issues for demonstration

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# S3 bucket with security issues (intentional for testing)
resource "aws_s3_bucket" "app_logs" {
  bucket = "my-app-logs-bucket-demo"
  
  tags = {
    Name        = "Application Logs"
    Environment = "demo"
  }
}

# Missing encryption configuration - security issue!
# resource "aws_s3_bucket_server_side_encryption_configuration" "app_logs_encryption" {
#   bucket = aws_s3_bucket.app_logs.id
#   rule {
#     apply_server_side_encryption_by_default {
#       sse_algorithm = "AES256"
#     }
#   }
# }

# Public bucket access - security issue!
resource "aws_s3_bucket_public_access_block" "app_logs_pab" {
  bucket = aws_s3_bucket.app_logs.id

  block_public_acls       = false  # Should be true
  block_public_policy     = false  # Should be true
  ignore_public_acls      = false  # Should be true
  restrict_public_buckets = false  # Should be true
}

# Security group with overly permissive rules
resource "aws_security_group" "web_sg" {
  name_prefix = "web-server-"
  description = "Security group for web server"

  # Overly permissive inbound rules - security issue!
  ingress {
    description = "HTTP from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Should be more restrictive
  }

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Should be more restrictive
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "web-server-sg"
  }
} 