# Ansible deployment: CentOS 7 monitoring stack and RHEL 8 node_exporter

This playbook starts the Prometheus installation already present on CentOS 7; it
does not download or replace Prometheus. It adds Alertmanager, Grafana, a
single-server Consul catalog, and Consul service discovery for node_exporter on
RHEL8-1. The RHEL8-1 play installs both node_exporter and its Consul client.

CentOS 7 is end-of-life. The default Alertmanager, Grafana, and Consul versions
are legacy compatibility pins, not currently supported releases. Upgrade the
operating system and update these pins before using this as a production
deployment. Downloads are version-pinned. Consul's archive checksum is verified; add
verified upstream SHA-256 values for Alertmanager and node_exporter before
production use.

## Prepare

1. Copy `inventory.ini.example` to `inventory.ini` and replace the example
   addresses with the real hosts. The example uses the reserved `192.0.2.0/24`
   documentation network and will not connect as-is.
2. Ensure Ansible can SSH to both hosts using a non-root account with sudo.
   Configure SSH keys and privilege escalation outside this repository; do not
   put passwords or private keys in the inventory. Both targets must have a
   Python interpreter supported by the Ansible version on the controller.
   Current Ansible releases do not support CentOS 7's stock Python 2; install a
   supported Python interpreter there and set `ansible_python_interpreter` in
   the inventory if Ansible does not discover it automatically.
3. On CentOS 7, confirm the existing unit is `prometheus.service`, the config
   is `/etc/prometheus/prometheus.yml`, and `promtool` is at
   `/usr/local/bin/promtool`. Override `prometheus_service_name`,
   `prometheus_config_file`, and `prometheus_promtool_path` in
   `group_vars/all.yml` if your installation differs.
4. Confirm the Prometheus config has a top-level `scrape_configs:` section.
   The playbook validates the existing config, adds a managed Consul scrape
   job, validates again, and restarts the existing Prometheus service when
   that config changes. It makes a backup before editing.

Run from this directory:

```sh
ansible-playbook -i inventory.ini site.yml --syntax-check
ansible-playbook -i inventory.ini site.yml --check --diff
ansible-playbook -i inventory.ini site.yml
```

CentOS 7 package repositories may need to be pointed at the archived CentOS
Vault before the `unzip` package can be installed. The playbook does not change
repository configuration.

## Network and application configuration

Allow only the required traffic between trusted monitoring hosts:

- TCP 8301 between the Consul server and client agents (Consul LAN gossip).
- TCP 8300 from RHEL8-1's Consul agent to the CentOS 7 Consul server (server
  RPC).
- TCP 9100 from the monitoring network to RHEL8-1.
- TCP 3000 from Grafana users to CentOS 7, if Grafana is remotely accessed.
- TCP 9093 from Prometheus to Alertmanager, if Prometheus alerting is configured.

The Consul HTTP API listens on loopback on the CentOS 7 server. Do not expose
Consul ports to untrusted networks. This sample does not configure Consul ACLs
or gossip encryption and is intended only for a trusted, isolated network.

The installed Alertmanager config has a placeholder `default` receiver and
does not deliver notifications. Add a real receiver and route before relying on
alerts. Configure Prometheus's top-level `alerting.alertmanagers` section
separately if it is not already present. The playbook preserves all existing
Prometheus scrape jobs and only manages its marked Consul discovery block.

Grafana is installed but no data source or dashboard is provisioned. After
deployment, configure a Prometheus data source pointing at
`http://127.0.0.1:9090` from the Grafana host.

## Verify

```sh
ansible -i inventory.ini monitoring -b -m command -a "systemctl is-active prometheus alertmanager grafana-server consul"
ansible -i inventory.ini node_exporters -b -m command -a "systemctl is-active node_exporter consul"
```

Check `http://RHEL8-1:9100/metrics`, the Prometheus Targets page, and the Consul
catalog on the CentOS 7 host. The expected Prometheus job name is
`consul-node-exporters`.
