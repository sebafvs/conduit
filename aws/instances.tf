resource "aws_instance" "node" {
  for_each = var.nodes

  ami           = data.aws_ami.ubuntu.id
  instance_type = var.instance_type
  subnet_id     = aws_subnet.main.id
  key_name      = aws_key_pair.node[each.key].key_name
  vpc_security_group_ids = [
    each.value.role == "relay" ? aws_security_group.relay.id : aws_security_group.redirector.id,
  ]

  root_block_device {
    volume_size           = 20
    volume_type           = "gp3"
    delete_on_termination = true
  }

  tags = {
    Name = "${var.project_tag}-${each.key}"
    Role = each.value.role
  }
}
