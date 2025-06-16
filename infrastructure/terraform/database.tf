# Database Infrastructure with High Availability and Disaster Recovery

# RDS Subnet Group
resource "aws_db_subnet_group" "main" {
  name       = "${var.cluster_name}-db-subnet-group"
  subnet_ids = aws_subnet.private[*].id

  tags = merge(local.common_tags, {
    Name = "${var.cluster_name}-db-subnet-group"
  })
}

# RDS Parameter Group for PostgreSQL optimization
resource "aws_db_parameter_group" "main" {
  family = "postgres15"
  name   = "${var.cluster_name}-pg15"

  parameter {
    name  = "shared_preload_libraries"
    value = "pg_stat_statements"
  }

  parameter {
    name  = "log_statement"
    value = "all"
  }

  parameter {
    name  = "log_min_duration_statement"
    value = "1000" # Log queries taking longer than 1 second
  }

  parameter {
    name  = "max_connections"
    value = "200"
  }

  parameter {
    name  = "work_mem"
    value = "16384" # 16MB
  }

  parameter {
    name  = "maintenance_work_mem"
    value = "524288" # 512MB
  }

  parameter {
    name  = "effective_cache_size"
    value = "2097152" # 2GB
  }

  tags = local.common_tags
}

# Security Group for RDS
resource "aws_security_group" "rds" {
  name_prefix = "${var.cluster_name}-rds-"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.nodes.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${var.cluster_name}-rds-sg"
  })
}

# Primary RDS Instance (Multi-AZ)
resource "aws_db_instance" "main" {
  identifier = "${var.cluster_name}-primary"

  engine         = "postgres"
  engine_version = "15.4"
  instance_class = var.db_instance_class

  allocated_storage     = var.db_allocated_storage
  max_allocated_storage = var.db_max_allocated_storage
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id           = aws_kms_key.cluster.arn

  db_name  = var.db_name
  username = var.db_username
  password = random_password.db_password.result

  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name
  parameter_group_name   = aws_db_parameter_group.main.name

  # High Availability
  multi_az = true

  # Backup and Maintenance
  backup_retention_period = 30
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"

  # Monitoring
  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_monitoring.arn
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  # Security
  deletion_protection = var.environment == "production" ? true : false
  skip_final_snapshot = var.environment == "production" ? false : true
  final_snapshot_identifier = var.environment == "production" ? "${var.cluster_name}-final-snapshot-${formatdate("YYYY-MM-DD-hhmm", timestamp())}" : null

  # Performance Insights
  performance_insights_enabled = true
  performance_insights_retention_period = 7
  performance_insights_kms_key_id = aws_kms_key.cluster.arn

  tags = merge(local.common_tags, {
    Name = "${var.cluster_name}-primary-db"
  })
}

# Read Replica for performance scaling
resource "aws_db_instance" "read_replica" {
  count = var.create_read_replica ? 1 : 0

  identifier = "${var.cluster_name}-read-replica"

  replicate_source_db = aws_db_instance.main.identifier
  instance_class      = var.db_instance_class

  # Performance Insights
  performance_insights_enabled = true
  performance_insights_retention_period = 7
  performance_insights_kms_key_id = aws_kms_key.cluster.arn

  # Monitoring
  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_monitoring.arn

  tags = merge(local.common_tags, {
    Name = "${var.cluster_name}-read-replica-db"
  })
}

# IAM role for RDS monitoring
resource "aws_iam_role" "rds_monitoring" {
  name = "${var.cluster_name}-rds-monitoring-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
  role       = aws_iam_role.rds_monitoring.name
}

# ElastiCache Redis Cluster for caching
resource "aws_elasticache_subnet_group" "main" {
  name       = "${var.cluster_name}-cache-subnet"
  subnet_ids = aws_subnet.private[*].id

  tags = local.common_tags
}

resource "aws_security_group" "redis" {
  name_prefix = "${var.cluster_name}-redis-"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.nodes.id]
  }

  tags = merge(local.common_tags, {
    Name = "${var.cluster_name}-redis-sg"
  })
}

resource "aws_elasticache_replication_group" "main" {
  replication_group_id       = "${var.cluster_name}-redis"
  description                = "Redis cluster for ${var.cluster_name}"

  node_type            = var.redis_node_type
  port                 = 6379
  parameter_group_name = "default.redis7"

  num_cache_clusters = var.redis_num_cache_nodes
  engine_version     = "7.0"

  subnet_group_name  = aws_elasticache_subnet_group.main.name
  security_group_ids = [aws_security_group.redis.id]

  # High Availability
  automatic_failover_enabled = true
  multi_az_enabled           = true

  # Security
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  kms_key_id                = aws_kms_key.cluster.arn

  # Backup
  snapshot_retention_limit = 7
  snapshot_window         = "05:00-06:00"

  # Maintenance
  maintenance_window = "sun:06:00-sun:07:00"

  # Notifications
  notification_topic_arn = aws_sns_topic.alerts.arn

  # Logging
  log_delivery_configuration {
    destination      = aws_cloudwatch_log_group.redis.name
    destination_type = "cloudwatch-logs"
    log_format       = "text"
    log_type         = "slow-log"
  }

  tags = local.common_tags
}

# CloudWatch log group for Redis
resource "aws_cloudwatch_log_group" "redis" {
  name              = "/aws/elasticache/${var.cluster_name}"
  retention_in_days = 14
  kms_key_id        = aws_kms_key.cluster.arn

  tags = local.common_tags
}

# SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name              = "${var.cluster_name}-alerts"
  kms_master_key_id = aws_kms_key.cluster.arn

  tags = local.common_tags
}

# Database variables
variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.r6g.xlarge"
}

variable "db_allocated_storage" {
  description = "RDS allocated storage in GB"
  type        = number
  default     = 100
}

variable "db_max_allocated_storage" {
  description = "RDS maximum allocated storage in GB"
  type        = number
  default     = 1000
}

variable "db_name" {
  description = "Database name"
  type        = string
  default     = "claude_deployment"
}

variable "db_username" {
  description = "Database username"
  type        = string
  default     = "claude_admin"
}

variable "create_read_replica" {
  description = "Create read replica for the database"
  type        = bool
  default     = true
}

variable "redis_node_type" {
  description = "Redis node type"
  type        = string
  default     = "cache.r7g.large"
}

variable "redis_num_cache_nodes" {
  description = "Number of Redis cache nodes"
  type        = number
  default     = 3
}

# Database outputs
output "db_endpoint" {
  description = "RDS instance endpoint"
  value       = aws_db_instance.main.endpoint
  sensitive   = true
}

output "db_password" {
  description = "RDS instance password"
  value       = random_password.db_password.result
  sensitive   = true
}

output "redis_endpoint" {
  description = "Redis primary endpoint"
  value       = aws_elasticache_replication_group.main.primary_endpoint_address
  sensitive   = true
}

output "redis_configuration_endpoint" {
  description = "Redis configuration endpoint"
  value       = aws_elasticache_replication_group.main.configuration_endpoint_address
  sensitive   = true
}