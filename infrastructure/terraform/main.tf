# Production Infrastructure as Code for Claude Optimized Deployment
# Multi-cloud deployment with high availability and disaster recovery

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.20"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.10"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }

  backend "s3" {
    bucket         = "claude-deployment-terraform-state"
    key            = "production/terraform.tfstate"
    region         = "us-west-2"
    encrypt        = true
    dynamodb_table = "claude-deployment-terraform-locks"
  }
}

# Variables
variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "cluster_name" {
  description = "EKS cluster name"
  type        = string
  default     = "claude-deployment-prod"
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "Availability zones"
  type        = list(string)
  default     = ["us-west-2a", "us-west-2b", "us-west-2c"]
}

variable "node_instance_types" {
  description = "Instance types for worker nodes"
  type        = list(string)
  default     = ["m5.xlarge", "m5.2xlarge"]
}

variable "min_node_count" {
  description = "Minimum number of worker nodes"
  type        = number
  default     = 3
}

variable "max_node_count" {
  description = "Maximum number of worker nodes"
  type        = number
  default     = 20
}

variable "desired_node_count" {
  description = "Desired number of worker nodes"
  type        = number
  default     = 6
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Local values
locals {
  common_tags = {
    Environment = var.environment
    Project     = "claude-deployment"
    Terraform   = "true"
    Owner       = "claude-deployment-team"
  }
}

# Random password for database
resource "random_password" "db_password" {
  length  = 32
  special = true
}

# VPC and Networking
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(local.common_tags, {
    Name = "${var.cluster_name}-vpc"
  })
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = merge(local.common_tags, {
    Name = "${var.cluster_name}-igw"
  })
}

resource "aws_subnet" "public" {
  count = length(var.availability_zones)

  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = true

  tags = merge(local.common_tags, {
    Name                        = "${var.cluster_name}-public-${count.index + 1}"
    "kubernetes.io/role/elb"    = "1"
    "kubernetes.io/cluster/${var.cluster_name}" = "owned"
  })
}

resource "aws_subnet" "private" {
  count = length(var.availability_zones)

  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 10)
  availability_zone = var.availability_zones[count.index]

  tags = merge(local.common_tags, {
    Name                            = "${var.cluster_name}-private-${count.index + 1}"
    "kubernetes.io/role/internal-elb" = "1"
    "kubernetes.io/cluster/${var.cluster_name}" = "owned"
  })
}

# NAT Gateways for private subnet internet access
resource "aws_eip" "nat" {
  count = length(var.availability_zones)
  domain = "vpc"

  tags = merge(local.common_tags, {
    Name = "${var.cluster_name}-nat-eip-${count.index + 1}"
  })

  depends_on = [aws_internet_gateway.main]
}

resource "aws_nat_gateway" "main" {
  count = length(var.availability_zones)

  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = merge(local.common_tags, {
    Name = "${var.cluster_name}-nat-${count.index + 1}"
  })

  depends_on = [aws_internet_gateway.main]
}

# Route tables
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = merge(local.common_tags, {
    Name = "${var.cluster_name}-public-rt"
  })
}

resource "aws_route_table" "private" {
  count = length(var.availability_zones)

  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[count.index].id
  }

  tags = merge(local.common_tags, {
    Name = "${var.cluster_name}-private-rt-${count.index + 1}"
  })
}

resource "aws_route_table_association" "public" {
  count = length(var.availability_zones)

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count = length(var.availability_zones)

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# Security Groups
resource "aws_security_group" "cluster" {
  name_prefix = "${var.cluster_name}-cluster-"
  vpc_id      = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${var.cluster_name}-cluster-sg"
  })
}

resource "aws_security_group" "nodes" {
  name_prefix = "${var.cluster_name}-nodes-"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port = 0
    to_port   = 65535
    protocol  = "tcp"
    self      = true
  }

  ingress {
    from_port       = 1025
    to_port         = 65535
    protocol        = "tcp"
    security_groups = [aws_security_group.cluster.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${var.cluster_name}-nodes-sg"
  })
}

# KMS Key for encryption
resource "aws_kms_key" "cluster" {
  description             = "EKS cluster encryption key"
  deletion_window_in_days = 7

  tags = merge(local.common_tags, {
    Name = "${var.cluster_name}-key"
  })
}

resource "aws_kms_alias" "cluster" {
  name          = "alias/${var.cluster_name}"
  target_key_id = aws_kms_key.cluster.key_id
}

# Output values
output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

output "private_subnet_ids" {
  description = "Private subnet IDs"
  value       = aws_subnet.private[*].id
}

output "public_subnet_ids" {
  description = "Public subnet IDs"
  value       = aws_subnet.public[*].id
}

output "cluster_security_group_id" {
  description = "Cluster security group ID"
  value       = aws_security_group.cluster.id
}

output "node_security_group_id" {
  description = "Node security group ID"
  value       = aws_security_group.nodes.id
}

output "kms_key_id" {
  description = "KMS key ID"
  value       = aws_kms_key.cluster.id
}