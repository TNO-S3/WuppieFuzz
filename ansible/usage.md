# Usage: Registering a GitHub Self-Hosted Runner

This document describes the procedure to register a GitHub self-hosted runner using Ansible.

---

## Prerequisites

* Access to the GitHub organization or repository
* Permission to manage self-hosted runners
* Ansible installed and configured
* Target host accessible via SSH

---

# Step 1 – Create a GitHub Personal Access Token (PAT)

To register or remove self-hosted runners, you need a **GitHub Personal Access Token (PAT)** with sufficient permissions.

## 1.1 Generate the PAT

1. Log in to GitHub.
2. Click your profile picture → **Settings**
3. Navigate to **Developer settings**
4. Select **Personal access tokens**
5. Click **Generate new token**

You can use either:

* **Fine-grained token (recommended)**
* **Classic token**

---

## 1.2 Required Permissions

### If using a Fine-Grained Token

Grant the following permissions:

* **Repository permissions**

  * Administration: `Read and Write`

* **Organization permissions** (if registering at org level)

  * Self-hosted runners: `Read and Write`

---

### If using a Classic Token

Enable the following scopes:

```
repo
admin:org
workflow
```

---

## 1.3 Store the Token Securely

Store the PAT securely. For example:

```bash
export GITHUB_PAT=<your_token_here>
```

Or store it in an encrypted Ansible Vault file.

---

# Step 2 – Execute the Ansible Command

Run the Ansible playbook responsible for registering the GitHub runner.

Example:

```bash
export GITHUB_TOKEN=github_pat_xxxxx
ansible-playbook -i inventory.yml install.yml -e "github_token=$GITHUB_TOKEN"
```

### Parameters

| Variable      | Description                    |
| ------------- | ------------------------------ |
| `github_token`  | GitHub Personal Access Token   |

---

## What the Playbook Does

* Requests a runner registration token from GitHub
* Downloads the GitHub runner package
* Configures the runner
* Installs it as a service
* Starts the runner service

---

# Step 3 – Validate the Runner Registration

After execution, verify that the runner is properly registered.

---

## 3.1 Validate in GitHub UI

### Organization Level

1. Go to your GitHub Organization
2. Navigate to:

```
Settings → Actions → Runners
```

3. Confirm the new runner appears in the list
4. Ensure its status is:

```
Idle
```

---

### Repository Level

1. Go to the repository
2. Navigate to:

```
Settings → Actions → Runners
```

3. Confirm the runner is listed and online

---

## 3.2 Validate on the Target Host

Check the runner service:

```bash
sudo systemctl status actions.runner.*
```

You should see:

```
Active: active (running)
```

---

## 3.3 Optional – Test with a Workflow

Trigger a test workflow using:

```yaml
runs-on: [self-hosted]
```

Confirm the job is picked up by the newly registered runner.

---

# Troubleshooting

## Runner Not Appearing

* Verify PAT permissions
* Confirm correct organization/repository scope
* Check Ansible playbook logs

## Runner Offline

* Restart service:

```bash
sudo systemctl restart actions.runner.*
```

* Check network connectivity to GitHub

---

# Security Recommendations

* Use Fine-Grained PATs whenever possible
* Store tokens in Ansible Vault
* Rotate PATs regularly
* Restrict runner access using labels

---

