variable "region" {
  description = "AWS Region"
  default     = "ap-south-1"
}

variable "vpc_cidr" {
  description = "CIDR block for main"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  type    = string
  default = "ap-south-1a"
}
