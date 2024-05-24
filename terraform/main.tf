################
### Provider ###
################
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.31.0"
    }
  }
}

provider "aws" {
  region = var.region
}

data "aws_availability_zones" "available" {
  state = "available"
}





#################
###    VPC    ###
#################
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  instance_tenancy     = "default"
  enable_dns_hostnames = true
  tags = {
    name = "main"
  }
}



resource "aws_subnet" "public_subnets" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true
  tags = {
    Name = "Public Subnet ${count.index + 1}"
  }
}

resource "aws_subnet" "private_subnets" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index + 2)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = false
  tags = {
    Name = "Private Subnet ${count.index + 1}"
  }
}


resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "Internet_Gateway"
  }
}

resource "aws_route_table" "public_route_table" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
}

resource "aws_route_table_association" "public_route" {
  count          = length(aws_subnet.public_subnets)
  subnet_id      = aws_subnet.public_subnets[count.index].id
  route_table_id = aws_route_table.public_route_table.id
}


#################
# Load Balancer #
#################
resource "aws_lb" "spam_detection_lb" {
  name               = "spam-detection-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.lb_sg.id]
  subnets            = aws_subnet.public_subnets[*].id
}

resource "aws_lb_listener" "spam_detection_listener" {
  load_balancer_arn = aws_lb.spam_detection_lb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.spam_detection_tg.arn
  }
}

resource "aws_lb_target_group" "spam_detection_tg" {
  name        = "spam-detection-tg"
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"
}


resource "aws_security_group" "lb_sg" {
  name   = "Load Balancer Security Group"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "app_sg" {
  name   = "Web Application Security Group"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    security_groups = [aws_security_group.lb_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

output "load_balancer_dns_name" {
  description = "DNS name of the load balancer"
  value       = aws_lb.spam_detection_lb.dns_name
}

#################
## ECS Cluster ##
#################
resource "aws_iam_role" "ecs_task_execution_role" {
  name = "ecs-task-execution-role"

  assume_role_policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "Service": "ecs-tasks.amazonaws.com"
        },
        "Action": "sts:AssumeRole"
      }
    ]
  }
  EOF
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution_role_policy" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
  role       = aws_iam_role.ecs_task_execution_role.name
}




resource "aws_ecr_repository" "spam_detection_webapp" {
  name = "spam-detection-webapp"
}
data "aws_ecr_repository" "spam_detection_webapp" {
  name = "spam-detection-webapp"
}


resource "aws_ecr_repository" "spam_mysqldb" {
  name = "spam-mysqldb"
}
data "aws_ecr_repository" "spam_mysqldb" {
  name = "spam-mysqldb"
}


resource "aws_ecs_cluster" "spam_detection_cluster" {
  name = "spam-detection-cluster"
}

resource "aws_ecs_task_definition" "spam_mysqldb" {
  family                = "spam-mysqldb"
  container_definitions = <<DEFINITION
[
  {
    "name": "spam-mysqldb",
    "image": "${data.aws_ecr_repository.spam_mysqldb.repository_url}:latest",
    "portMappings": [
      {
        "containerPort": 3306,
        "hostPort": 3306
      }
    ],
    "environment": [
      {
        "name": "MYSQL_DATABASE",
        "value": "spam_user_db"
      },
      {
        "name": "MYSQL_USER",
        "value": "admino"
      },
      {
        "name": "MYSQL_ROOT_PASSWORD",
        "value": "SpamMysql@1234"
      },
      {
        "name": "MYSQL_HOST",
        "value": "spam-mysqldb"
      }
    ],
    "mountPoints": [
      {
        "sourceVolume": "mysql_data",
        "containerPath": "/var/lib/mysql"
      }
    ]
  }
]
DEFINITION
  volume {
    name = "mysql_data"
  }
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 1024
  memory                   = 2048
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.name
}

resource "aws_ecs_task_definition" "spam_detection_webapp" {
  family                   = "spam-detection-webapp"
  container_definitions    = <<DEFINITION
  [
  {
    "name": "spam-detection-webapp",
    "image": "${data.aws_ecr_repository.spam_detection_webapp.repository_url}:latest",
    "portMappings": [
      {
        "containerPort": 8000,
        "hostPort": 8000
      }
    ],
    "environment": [
      {
        "name": "DJANGO_SETTINGS_MODULE",
        "value": "spam_mail_project.settings"
      },
      {
        "name": "DB_NAME",
        "value": "spam_user_db"
      },
      {
        "name": "DB_USER",
        "value": "admino"
      },
      {
        "name": "DB_PASSWORD",
        "value": "SpamMysql@1234"
      },
      {
        "name": "DB_HOST",
        "value": "spam-mysqldb"
      }
    ],
    "links": [
      "spam-mysqldb:external-mysql"
    ]
  }
]
DEFINITION
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 1024
  memory                   = 2048
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.name
}



resource "aws_ecs_service" "spam_mysqldb" {
  name            = "spam-mysqldb"
  cluster         = aws_ecs_cluster.spam_detection_cluster.id
  task_definition = aws_ecs_task_definition.spam_mysqldb.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.private_subnets[*].id
    security_groups  = [aws_security_group.app_sg.id]
    assign_public_ip = false
  }
}

resource "aws_ecs_service" "spam_detection_webapp" {
  name            = "spam-detection-webapp"
  cluster         = aws_ecs_cluster.spam_detection_cluster.id
  task_definition = aws_ecs_task_definition.spam_detection_webapp.arn
  desired_count   = 2
  launch_type     = "FARGATE"

  load_balancer {
    target_group_arn = aws_lb_target_group.spam_detection_tg.arn
    container_name   = "spam-detection-webapp"
    container_port   = 8000
  }

  network_configuration {
    subnets          = aws_subnet.private_subnets[*].id
    security_groups  = [aws_security_group.app_sg.id]
    assign_public_ip = true
  }
}