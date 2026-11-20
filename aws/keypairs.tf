resource "tls_private_key" "node" {
  for_each = var.nodes

  algorithm = "ED25519"
}

resource "aws_key_pair" "node" {
  for_each = var.nodes

  key_name   = "${var.project_tag}-${each.key}"
  public_key = tls_private_key.node[each.key].public_key_openssh

  tags = { Name = "${var.project_tag}-key-${each.key}" }
}

resource "local_file" "node_private_key" {
  for_each = var.nodes

  filename        = "${var.ssh_key_dir}/${each.value.key_stem}.pem"
  content         = tls_private_key.node[each.key].private_key_openssh
  file_permission = "0600"
}
