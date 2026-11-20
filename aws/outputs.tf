output "nodes" {
  description = "Per-node summary: public IP, role, SSH key path, instance ID. Ready to paste into conduit full.yml."
  value = {
    for name, _ in var.nodes :
    name => {
      role        = var.nodes[name].role
      public_ip   = aws_instance.node[name].public_ip
      private_ip  = aws_instance.node[name].private_ip
      ssh_key     = local_file.node_private_key[name].filename
      instance_id = aws_instance.node[name].id
      ami         = aws_instance.node[name].ami
    }
  }
}

output "public_ips" {
  description = "Flat map node → public IP. Easiest to feed into templating."
  value       = { for name, _ in var.nodes : name => aws_instance.node[name].public_ip }
}

output "ssh_key_paths" {
  description = "Flat map node → local PEM path."
  value       = { for name, _ in var.nodes : name => local_file.node_private_key[name].filename }
}

output "vpc_id" {
  value = aws_vpc.main.id
}

output "subnet_id" {
  value = aws_subnet.main.id
}

output "sg_relay_id" {
  value = aws_security_group.relay.id
}

output "sg_redirector_id" {
  value = aws_security_group.redirector.id
}
