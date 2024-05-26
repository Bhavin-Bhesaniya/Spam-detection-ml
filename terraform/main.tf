# ################
# ### Provider ###
# ################
# terraform {
#   required_providers {
#     aws = {
#       source  = "hashicorp/aws"
#       version = "5.17.0"
#     }
#   }
# }

# provider "aws" {
#   region = "ap-south-1"
# }

# data "aws_availability_zones" "available" {
#   state = "available"
# }

# #################
# ###    VPC    ###
# #################
# locals {
#   azs_count = 2
#   azs_names = data.aws_availability_zones.available.names
# }

# resource "aws_vpc" "main" {
#   cidr_block           = "10.10.0.0/16"
#   instance_tenancy     = "default"
#   enable_dns_hostnames = true
#   tags                 = { Name = "main" }
# }

# resource "aws_subnet" "public" {
#   count                   = 2
#   vpc_id                  = aws_vpc.main.id
#   availability_zone       = data.aws_availability_zones.available.names[count.index]
#   cidr_block              = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index)
#   map_public_ip_on_launch = true
#   tags = {
#     Name = "Public Subnet ${count.index + 1}"
#   }
# }

# resource "aws_internet_gateway" "main" {
#   vpc_id = aws_vpc.main.id
#   tags = {
#     Name = "Internet_Gateway"
#   }
# }

# resource "aws_eip" "main" {
#   count      = local.azs_count
#   depends_on = [aws_internet_gateway.main]
#   tags       = { Name = "demo-eip-${local.azs_names[count.index]}" }
# }


# resource "aws_route_table" "public_route_table" {
#   vpc_id = aws_vpc.main.id
#   tags   = { Name = "demo-rt-public" }

#   route {
#     cidr_block = "0.0.0.0/0"
#     gateway_id = aws_internet_gateway.main.id
#   }
# }

# resource "aws_route_table_association" "public_route" {
#   count          = local.azs_count
#   subnet_id      = aws_subnet.public_route_table[count.index].id
#   route_table_id = aws_route_table.public_route_table.id
# }


# # # --- ECS ASG ---
# # resource "aws_autoscaling_group" "ecs" {
# #   name_prefix               = "demo-ecs-asg-"
# #   vpc_zone_identifier       = aws_subnet.public[*].id
# #   min_size                  = 2
# #   max_size                  = 8
# #   health_check_grace_period = 0
# #   health_check_type         = "EC2"
# #   protect_from_scale_in     = false

# #   launch_template {
# #     id      = aws_launch_template.ecs_ec2.id
# #     version = "$Latest"
# #   }

# #   tag {
# #     key                 = "Name"
# #     value               = "demo-ecs-cluster"
# #     propagate_at_launch = true
# #   }

# #   tag {
# #     key                 = "AmazonECSManaged"
# #     value               = ""
# #     propagate_at_launch = true
# #   }
# # }


# # # --- ECS Capacity Provider ---

# # resource "aws_ecs_capacity_provider" "main" {
# #   name = "demo-ecs-ec2"

# #   auto_scaling_group_provider {
# #     auto_scaling_group_arn         = aws_autoscaling_group.ecs.arn
# #     managed_termination_protection = "DISABLED"

# #     managed_scaling {
# #       maximum_scaling_step_size = 2
# #       minimum_scaling_step_size = 1
# #       status                    = "ENABLED"
# #       target_capacity           = 100
# #     }
# #   }
# # }

# # resource "aws_ecs_cluster_capacity_providers" "main" {
# #   cluster_name       = aws_ecs_cluster.main.name
# #   capacity_providers = [aws_ecs_capacity_provider.main.name]

# #   default_capacity_provider_strategy {
# #     capacity_provider = aws_ecs_capacity_provider.main.name
# #     base              = 1
# #     weight            = 100
# #   }
# # }


# # resource "aws_ecr_repository" "app" {
# #   name                 = "demo-app"
# #   image_tag_mutability = "MUTABLE"
# #   force_delete         = true

# #   image_scanning_configuration {
# #     scan_on_push = true
# #   }
# # }

# # output "demo_app_repo_url" {
# #   value = aws_ecr_repository.app.repository_url
# # }



# # # --- ECS Task Role ---
# resource "aws_iam_policy_document" "ecs_task_execution_role" {
#   name = "ecs-task-execution-role"
#   assume_role_policy = <<-EOF
#   {
#     "Version": "2012-10-17",
#     "Statement": [
#       {
#         "Effect": "Allow",
#         "Principal": {
#           "Service": "ec2.amazonaws.com"
#         },
#         "Action": "sts:AssumeRole"
#       }
#     ]
#   }
#   EOF
# }

# resource "aws_iam_role_policy_attachment" "ecs_task_execution_role_policy" {
#   policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
#   role       = aws_iam_role.ecs_task_execution_role.name
# }

# data "aws_ecr_repository" "spam_detection_webapp" {
#   name = "spam-detection-webapp"
# }

# data "aws_ecr_repository" "spam_mysqldb" {
#   name = "spam-mysqldb"
# }

# # # --- Cloud Watch Logs ---

# # resource "aws_cloudwatch_log_group" "ecs" {
# #   name              = "/ecs/demo"
# #   retention_in_days = 14
# # }

# # # --- ECS Task Definition ---
# # resource "aws_ecs_task_definition" "app" {
# #   family             = "demo-app"
# #   task_role_arn      = aws_iam_role.ecs_task_role.arn
# #   execution_role_arn = aws_iam_role.ecs_exec_role.arn
# #   network_mode       = "awsvpc"
# #   cpu                = 256
# #   memory             = 256

# #   container_definitions = jsonencode([{
# #     name         = "app",
# #     image        = "${aws_ecr_repository.app.repository_url}:latest",
# #     essential    = true,
# #     portMappings = [{ containerPort = 80, hostPort = 80 }],

# #     environment = [
# #       { name = "EXAMPLE", value = "example" }
# #     ]

# #     logConfiguration = {
# #       logDriver = "awslogs",
# #       options = {
# #         "awslogs-region"        = "ap-south-1",
# #         "awslogs-group"         = aws_cloudwatch_log_group.ecs.name,
# #         "awslogs-stream-prefix" = "app"
# #       }
# #     },
# #   }])
# # }


# # # --- ECS Service ---

# # resource "aws_security_group" "ecs_task" {
# #   name_prefix = "ecs-task-sg-"
# #   description = "Allow all traffic within the VPC"
# #   vpc_id      = aws_vpc.main.id

# #   ingress {
# #     from_port   = 0
# #     to_port     = 0
# #     protocol    = "-1"
# #     cidr_blocks = [aws_vpc.main.cidr_block]
# #   }

# #   egress {
# #     from_port   = 0
# #     to_port     = 0
# #     protocol    = "-1"
# #     cidr_blocks = ["0.0.0.0/0"]
# #   }
# # }

# # resource "aws_ecs_service" "app" {
# #   name            = "app"
# #   cluster         = aws_ecs_cluster.main.id
# #   task_definition = aws_ecs_task_definition.app.arn
# #   desired_count   = 2

# #   network_configuration {
# #     security_groups = [aws_security_group.ecs_task.id]
# #     subnets         = aws_subnet.public[*].id
# #   }

# #   capacity_provider_strategy {
# #     capacity_provider = aws_ecs_capacity_provider.main.name
# #     base              = 1
# #     weight            = 100
# #   }

# #   ordered_placement_strategy {
# #     type  = "spread"
# #     field = "attribute:ecs.availability-zone"
# #   }

# #   lifecycle {
# #     ignore_changes = [desired_count]
# #   }
# #   depends_on = [aws_lb_target_group.app]
# #   load_balancer {
# #     target_group_arn = aws_lb_target_group.app.arn
# #     container_name   = "app"
# #     container_port   = 80
# #   }
# # }




# # # --- ALB ---
# resource "aws_security_group" "lb_sg" {
#   name_prefix = "http-sg-"
#   description = "Allow all HTTP/HTTPS traffic from public"
#   vpc_id      = aws_vpc.main.id

#   dynamic "ingress" {
#     for_each = [80, 443]
#     content {
#       protocol    = "tcp"
#       from_port   = ingress.value
#       to_port     = ingress.value
#       cidr_blocks = ["0.0.0.0/0"]
#     }
#   }

#   egress {
#     protocol    = "-1"
#     from_port   = 0
#     to_port     = 0
#     cidr_blocks = ["0.0.0.0/0"]
#   }
# }

# resource "aws_lb" "spam_detection_lb" {
#   name               = "spam-detection-lb"
#   load_balancer_type = "application"
#   subnets            = aws_subnet.public[*].id
#   security_groups    = [aws_security_group.lb_sg.id]
# }

# resource "aws_lb_target_group" "spam_detection_tg" {
#   name_prefix = "app-"
#   vpc_id      = aws_vpc.main.id
#   protocol    = "HTTP"
#   port        = 8000
#   target_type = "ip"

#   health_check {
#     enabled             = true
#     path                = "/"
#     port                = 80
#     matcher             = 200
#     interval            = 10
#     timeout             = 5
#     healthy_threshold   = 2
#     unhealthy_threshold = 3
#   }
# }

# resource "aws_lb_listener" "spam_detection_listener" {
#   load_balancer_arn = aws_lb.spam_detection_lb.arn
#   port              = 80
#   protocol          = "HTTP"

#   default_action {
#     type             = "forward"
#     target_group_arn = aws_lb_target_group.spam_detection_tg.id
#   }
# }

# output "alb_url" {
#   value = aws_lb.main.dns_name
# }

# resource "aws_security_group" "app_sg" {
#   name   = "Web Application Security Group"
#   vpc_id = aws_vpc.main.id

#   ingress {
#     from_port       = 0
#     to_port         = 0
#     protocol        = "-1"
#     security_groups = [aws_security_group.lb_sg.id]
#   }

#   ingress {
#     from_port       = 3306
#     to_port         = 3306
#     protocol        = "tcp"
#     security_groups = [aws_security_group.lb_sg.id]
#   }
#   egress {
#     from_port   = 0
#     to_port     = 0
#     protocol    = "-1"
#     cidr_blocks = ["0.0.0.0/0"]
#   }
# }

# output "load_balancer_dns_name" {
#   description = "DNS name of the load balancer"
#   value       = aws_lb.spam_detection_lb.dns_name
# }



# # # --- ECS Service Auto Scaling ---
# # resource "aws_appautoscaling_target" "ecs_target" {
# #   service_namespace  = "ecs"
# #   scalable_dimension = "ecs:service:DesiredCount"
# #   resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.app.name}"
# #   min_capacity       = 2
# #   max_capacity       = 5
# # }

# # resource "aws_appautoscaling_policy" "ecs_target_cpu" {
# #   name               = "application-scaling-policy-cpu"
# #   policy_type        = "TargetTrackingScaling"
# #   service_namespace  = aws_appautoscaling_target.ecs_target.service_namespace
# #   resource_id        = aws_appautoscaling_target.ecs_target.resource_id
# #   scalable_dimension = aws_appautoscaling_target.ecs_target.scalable_dimension

# #   target_tracking_scaling_policy_configuration {
# #     predefined_metric_specification {
# #       predefined_metric_type = "ECSServiceAverageCPUUtilization"
# #     }

# #     target_value       = 80
# #     scale_in_cooldown  = 300
# #     scale_out_cooldown = 300
# #   }
# # }

# # resource "aws_appautoscaling_policy" "ecs_target_memory" {
# #   name               = "application-scaling-policy-memory"
# #   policy_type        = "TargetTrackingScaling"
# #   resource_id        = aws_appautoscaling_target.ecs_target.resource_id
# #   scalable_dimension = aws_appautoscaling_target.ecs_target.scalable_dimension
# #   service_namespace  = aws_appautoscaling_target.ecs_target.service_namespace

# #   target_tracking_scaling_policy_configuration {
# #     predefined_metric_specification {
# #       predefined_metric_type = "ECSServiceAverageMemoryUtilization"
# #     }

# #     target_value       = 80
# #     scale_in_cooldown  = 300
# #     scale_out_cooldown = 300
# #   }
# # }
