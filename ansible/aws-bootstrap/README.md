# aws-bootstrap

One-shot Ansible playbook that installs AWS CLI v2 + Terraform on the teamserver and writes `~/.aws/credentials` + `~/.aws/config`. Idempotent; safe to re-run on a half-finished host.

## When to run

Once per fresh teamserver, before `terraform init` / `terraform apply` in `conduit/aws/`. Also safe to re-run to refresh credentials (e.g. after rotating the IAM access key).

## Prerequisites

- Ansible on the same host (the playbook runs `localhost + connection=local`).
- Apt-managed Debian or Ubuntu with sudo access as the invoking user.

Install ansible on a fresh teamserver:

```bash
apt-get update && apt-get install -y ansible
```

## Usage

```bash
cd /root/conduit/ansible/aws-bootstrap

AWS_ACCESS_KEY_ID='AKIA...' \
AWS_SECRET_ACCESS_KEY='...' \
AWS_REGION='eu-north-1' \
ansible-playbook -i inventory.yml aws-bootstrap.yml -vvv
```

Required env vars: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`.
Optional env vars: `AWS_REGION` (default `eu-north-1`), `AWS_OUTPUT_FORMAT` (default `json`), `AWS_PROFILE` (default `default`).

`-vvv` is the default per project convention (one flag debug the first time; no round-trip diagnosis).

## What it does

| Task | Idempotency guard |
|---|---|
| Install awscli v2 from the official bundle | `stat /usr/local/bin/aws` |
| Install terraform from HashiCorp apt repo | apt module (`state: present`) |
| Render `~/.aws/credentials` (chmod 600) | template; overwrite is the goal |
| Render `~/.aws/config` (chmod 600) | template; overwrite is the goal |
| Run `aws sts get-caller-identity` and assert `Arn` + `UserId` present | n/a (check-only) |

## Overrides

Non-root target user:

```bash
ansible-playbook -i inventory.yml aws-bootstrap.yml -vvv \
  -e aws_config_user=ubuntu -e aws_home_dir=/home/ubuntu
```

Alt region / profile:

```bash
AWS_REGION='us-east-1' AWS_PROFILE='red-team' ansible-playbook -i inventory.yml aws-bootstrap.yml -vvv
```

## What it does NOT do

- Create an IAM user (do that once in the AWS console).
- Provision any AWS infrastructure (that is `conduit/aws/*.tf` via Terraform).
- Deploy conduit itself or any node (that is the per-node apply flow in the step-by-step).

## Verify afterwards

```bash
aws sts get-caller-identity
terraform -version
ls -la ~/.aws/
```

Expected: ARN + UserId + Account in JSON output; Terraform version 1.9+; two files `credentials` and `config` at mode 600 under `~/.aws/`.
