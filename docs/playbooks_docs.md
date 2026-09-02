## Ansible playbooks documentation

This documentation briefly explains the setup workflow executed by the Ansible playbook `01 - Kubernetes Cluster Installation`. It configures a single-node Kubernetes v1.30 cluster on Ubuntu Server 24.04.

---

### Deployment Steps Breakdown

##### 1. System Prerequisites
* **Disable Swap**: Permanent deactivation; mandatory for kubelet stability.
* **Kernel Modules**: Loads and persists `overlay` (container filesystem) and `br_netfilter` (bridge networking).
* **Networking Parameters**: Enables IPv4 forwarding via `sysctl` and forces bridge traffic through `iptables`.

##### 2. Container Runtime (Containerd)
* **Dependencies**: Installs package utilities, Python tooling, and the `containerd` engine.
* **Cgroup Configuration**: Initializes configuration and enforces `SystemdCgroup = true` for OS resource alignment.

##### 3. Kubernetes Repository & Tooling
* **Repository**: Imports official GPG keys and appends the v1.30 APT repository source.
* **Core Binaries**: Installs `kubelet`, `kubeadm`, and `kubectl`.
* **Package Lock**: Applies `apt-mark hold` to lock binary versions against accidental OS upgrades.

##### 4. Cluster Initialization
* **Bootstrap**: Executes `kubeadm init` targeting the `192.168.0.0/16` Pod network pool.
* **User Permissions**: Provisions `~/.kube/config` with `0644` rights for secure, non-root `kubectl` usage.

##### 5. Network Plugin & Single-Node Adjustment
* **Calico CNI**: Deploys the Calico network engine for pod routing and network policy enforcement.
* **Remove Taint**: Deletes the `control-plane:NoSchedule` taint to allow scheduling workloads on the single node.

##### 6. Cluster Verification
* **Status Check**: Uses `kubectl wait` to block execution until the node reports a `Ready` condition.
* **Output Logging**: Captures and prints the finalized node runtime state directly to the terminal.
