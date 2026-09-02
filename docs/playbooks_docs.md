## Ansible playbooks documentation

This documentation briefly explains the setup workflow executed by the Ansible playbooks.

### Playbook  `01 - Kubernetes Cluster Installation`. 
It configures a single-node Kubernetes v1.30 cluster on Ubuntu Server 24.04.

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




### Playbook `02 - Security Stack Deployment (Falco + Prometheus + Grafana)`. 
It configures the monitoring and runtime security logging infrastructure on a single-node Kubernetes v1.30 cluster.

---

### Deployment Steps Breakdown

##### 1. Helm Installation & Setup
* **Package Manager**: Downloads and runs the official installation script to deploy Helm 3 binaries.
* **Repositories**: Indexes remote chart catalogs for `falcosecurity`, `prometheus-community`, and `grafana`.
* **Index Synchronization**: Refreshes the local system chart registry with up-to-date manifest packages.

##### 2. Namespace Creation
* **Segmentation**: Iterates through a continuous loop to set up `monitoring`, `security`, and `apps` partitions.
* **Idempotency Flow**: Generates structural dry-run text blueprints piped directly into standard creation commands to prevent re-execution errors.

##### 3. Dynamic Storage Engine
* **Rancher Provisioner**: Deploys an open-source local path controller file straight from an external Git registry.
* **Fallback Class**: Patches system labels with an active metadata trigger line to mark local storage as the global default.
##### 4. Metrics & Gateway Deployment
* **Prometheus Core**: Upgrades or installs data-scraping components inside the target `monitoring` namespace environment.
* **Network Exposure**: Exposes the system dashboard externally over physical machine port 30090 via a NodePort configuration.
* **Pushgateway**: Provisions an intermediary ingest mailbox to allow push-based metric updates from transient runtime event systems.

##### 5. Visualization Platform
* **Grafana Node**: Launches the visualization stack on node port 31281 utilizing explicit credential parameters.
* **Datasource Binding**: Automatically injects structural cluster environment URLs to hook Grafana straight into the Prometheus engine.


##### 6. Runtime Security Engine
* **Falco Agent**: Provisions kernel threat inspection inside the `security` namespace utilizing high-performance modern eBPF tracking.
* **Data Formatting**: Enforces structured JSON log outputs and standard output channels for threat intelligence event capturing.
* **Pipeline Integration**: Hooks up Falcosidekick telemetry routing to stream critical tracking lines directly into a targeted internal Kafka broker topic.

##### 7. Log Forwarding Scripting
* **Bridge Scripting**: Provisions an executable shell script tool inside the user's home folder tree structure.
* **Network Tunnels**: Establishes local background port forwarding paths to safely pipe metrics data through cluster api layers.
* **Scraping Pipeline**: Pairs real-time container log ingestion streams with python processing blocks to count events and dispatch numbers to Pushgateway.

##### 8. Fleet Verification
* **Pod Audit Scan**: Triggers global cluster commands to capture container runtime status across all environment blocks.
* **Output Logging**: Registers the final layout text array and outputs execution summaries onto the automation terminal screen.

### Playbook `03 - Deploy Kafka on Kubernetes`. 
It provisions a modern, single-node, ZooKeeperless Apache Kafka cluster operating in KRaft mode with persistent storage to act as the central event bus between Falco and the AI agent.

---

### Deployment Steps Breakdown

##### 1. Modular Orchestration (03-deploy_kafka.yml)
* **Role Delegation**: Keeps the primary playbook minimalist by outsourcing execution logic to a dedicated `kafka` Ansible role.
* **Context Mapping**: Injecting user-specific `KUBECONFIG` paths straight into the environment runtime layers ensures `kubectl` calls securely target the intended cluster.

##### 2. Role Execution (roles/kafka/tasks/main.yml)
* **Idempotent Provisioning**: Generates a dry-run text blueprint piped directly into standard creation commands to set up the `kafka-system` namespace without re-execution errors.
* **Artifact Traceability**: Provisions a dedicated directory on the cluster machine and syncs the static manifest payload to allow clear manual auditing and easier debugging.
* **Declarative Control**: Triggers a clean `kubectl apply` shell execution, decoupling orchestration logic (Ansible) from core resource state declaration (Kubernetes).

##### 3. Manifest Architecture (k8s/kafka/kafka-direct.yaml)
* **Logical Isolation**: Enforces a dedicated `kafka-system` namespace to align with the principle of least privilege.
* **Data Persistence**: Requests 1Gi of disk space via `kafka-data-pvc` leveraging the automated `local-path` StorageClass to guarantee that messages and offsets survive pod Restarts.
* **Headless Network Service**: Defines a `clusterIP: None` network protocol configuration to bypass standard virtual load-balancing, forcing the system DNS to map direct Pod addresses for native internal Kafka broker discovery.
* **KRaft Engine Configuration**: Combines broker and controller properties inside a single Confluent Kafka replica container version 7.6.0 deployment, dropping legacy ZooKeeper dependencies.
* **Listener & Storage Integration**: Points core runtime networking components to the internal cluster domain address (`kafka.kafka-system.svc.cluster.local`) and mounts the persistent volume path inside `/var/lib/kafka/data`.
