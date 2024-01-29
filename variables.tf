variable "project_id" {
  type        = string
  default     = "tst-xchg"
  description = "Project ID in which to deploy"
}

variable "region" {
  type        = string
  default     = "us-east4"
  description = "Region in which to deploy"
}
variable "region_zone" {
  default     = "us-east4-a"
}
