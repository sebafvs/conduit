# Conduit AWS (Terraform)

Terraform-managed EC2 infrastructure for a Conduit stack: one VPC + public subnet, two security groups (relay + redirector), and N instances (relay01, redir01, redir02 by default).

## What this creates

| Resource | Count | Notes |
|---|---|---|
| VPC | 1 | `10.100.0.0/16` by default. Chosen to not overlap with the Nebula overlay `10.99.0.0/24`. |
| Subnet (public, one AZ) | 1 | `10.100.1.0/24`, maps public IP on launch. |
| Internet gateway + route table | 1 | Default route `0.0.0.0/0 → igw`. |
| Security group `conduit-relay` | 1 | Inbound TCP 22 + UDP 4242 from `0.0.0.0/0`. |
| Security group `conduit-redirector` | 1 | Inbound TCP 22, 80, 443 + UDP 4242 from `0.0.0.0/0`. |
| EC2 keypair (per node) | N | ed25519. Private key written to `${ssh_key_dir}/<key_stem>.pem` chmod 600. |
| EC2 instance (per node) | N | Latest Ubuntu 24.04 LTS AMI, 20 GB gp3 root, `t3.micro` by default. |

## Prerequisites

- AWS CLI v2 installed and `aws sts get-caller-identity` returns your IAM user.
- Terraform 1.9+ installed.
- `${ssh_key_dir}` exists and is writable by the user running Terraform (default `/root/.ssh`).

## One-time setup

```bash
cd aws/
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars if you want to override region / instance_type / nodes.
terraform init
```

## Create the stack

```bash
terraform plan -out tfplan
terraform apply tfplan
```

Expected output (abridged):

```
Outputs:

nodes = {
  "redir01" = { "ami" = "ami-...", "instance_id" = "i-...", "private_ip" = "10.100.1.X", "public_ip" = "A.B.C.D", "role" = "redirector", "ssh_key" = "/root/.ssh/REDIRECTOR01.pem" }
  "redir02" = { ... }
  "relay01" = { "ami" = ..., "role" = "relay", "ssh_key" = "/root/.ssh/RELAY01.pem", ... }
}
```

Private keys land at the paths listed. Public IPs are the values you paste into `redirectors[].deploy.address` and `relays[].deploy.address` in `../examples/_private/local.yml` (Step 2 of `Conduit Setup Step By Step.md`).

Programmatic access:

```bash
terraform output -json nodes | jq
terraform output -raw public_ips    # map node → IP for scripting
```

## Teardown

```bash
terraform destroy
```

Releases every resource it created. No Elastic IPs are used, so there is no "detached EIP burning money" risk.

## Cost sanity

`t3.micro` is Free-Tier-eligible for the first 12 months of a new AWS account for 750 hours/month aggregate across all `t2.micro` + `t3.micro`. Three instances running 24/7 is ~2160 hours/month, three times the free bucket. If you only run the stack for engagement windows (say, 10 days), 3 × t3.micro × 10 × 24 = 720 hours, which fits inside one month's free bucket.

Outside the free tier, `t3.micro` in `eu-north-1` is roughly $0.0104/hour (~$7.50/month per instance running 24/7, as of late 2025).

Teardown with `terraform destroy` the moment you don't need the infra.

## Where the state lives

Local `terraform.tfstate` in this directory, gitignored. Contains the private key material (because `tls_private_key` persists), so this directory and its state must be kept at `chmod 700` and never committed. For team / multi-machine workflows, upgrade to an S3 backend with KMS encryption; one-liner change at the top of `main.tf`.
