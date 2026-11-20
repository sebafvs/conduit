variable "region" {
  description = "AWS region for all resources."
  type        = string
  default     = "eu-north-1"
}

variable "availability_zone" {
  description = "AZ for the single subnet. Must be inside var.region."
  type        = string
  default     = "eu-north-1a"
}

variable "instance_type" {
  description = "EC2 instance type for every node. t3.micro covers the 750h/month free tier if you run one at a time."
  type        = string
  default     = "t3.micro"
}

variable "vpc_cidr" {
  description = "CIDR for the conduit-managed VPC. Chosen to avoid the Nebula overlay 10.99.0.0/24."
  type        = string
  default     = "10.100.0.0/16"
}

variable "subnet_cidr" {
  description = "CIDR for the single public subnet inside the VPC."
  type        = string
  default     = "10.100.1.0/24"
}

variable "ssh_key_dir" {
  description = "Directory on the teamserver where PEM keys land. Must exist and be writable by the user running terraform."
  type        = string
  default     = "/root/.ssh"
}

variable "project_tag" {
  description = "Value for the Project tag applied to every AWS resource. Lets you filter in Cost Explorer."
  type        = string
  default     = "conduit"
}

variable "nodes" {
  description = "Node name → role + ssh key filename stem. 'relay' and 'redirector' are the only valid roles."
  type = map(object({
    role     = string
    key_stem = string
  }))
  default = {
    relay01 = { role = "relay", key_stem = "RELAY01" }
    redir01 = { role = "redirector", key_stem = "REDIRECTOR01" }
    redir02 = { role = "redirector", key_stem = "REDIRECTOR02" }
  }

  validation {
    condition     = alltrue([for n in var.nodes : contains(["relay", "redirector"], n.role)])
    error_message = "Each node.role must be 'relay' or 'redirector'."
  }
}
