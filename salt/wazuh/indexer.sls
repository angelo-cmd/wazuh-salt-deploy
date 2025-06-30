{% set wazuh_indexer_nodes = pillar.get('wazuh', {}).get('nodes', {}).get('indexer', []) %}
{% set current_node==none %}
{% for node in wazuh_indexer_nodes %}
  {% if node.get('ip')==current_ip %}
    {%set current_node=node%}
  {% endif %}
{% endfor %}
# Ensure dependencies are installed
wazuh-indexer-deps:
  pkg.installed:
    - pkgs:
      - coreutils
      - curl
      - apt-transport-https

# Import Wazuh GPG key
wazuh_gpg_key:
  cmd.run:
    - name: >
        curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH |
        gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import &&
        chmod 644 /usr/share/keyrings/wazuh.gpg
    - unless: test -f /usr/share/keyrings/wazuh.gpg

# Add Wazuh apt repo
wazuh_apt_repo:
  file.append:
    - name: /etc/apt/sources.list.d/wazuh.list
    - text: 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main'
    - require:
      - cmd: wazuh_gpg_key
# Update apt cache after adding repo
apt_update:
  cmd.run:
    - name: apt-get update
    - require:
      - file: wazuh_apt_repo
# Download cert tool to /root if missing
download_wazuh_tools:
  cmd.run:
    - name: curl -sO https://packages.wazuh.com/4.12/wazuh-certs-tool.sh
    - cwd: /root
    - creates: /root/wazuh-certs-tool.sh

# Place config.yml under /root
/root/config.yml:
  file.managed:
    - source: salt://wazuh/files/config.yml.jinja
    - template: jinja
    - user: root
    - group: root
    - mode: 644


# Generate certs using the tool in /root
generate_wazuh_certs:
  cmd.run:
    - name: bash  /root/wazuh-certs-tool.sh -A
    - unless: test -f /root/wazuh-certificates/admin.pem
    - require:
      - file: /root/config.yml
compress_certificates:
  cmd.run:
    - name:  tar -cvf /root/wazuh-certificates.tar -C /root/wazuh-certificates/ .
    - require:
      - cmd: generate_wazuh_certs

wazuh_indexer_pkg:
  pkg.installed:
    - name: wazuh-indexer
    - require:
      - cmd: apt_update
# Ensure target cert dir exists
deploy_wazuh_certs_dir:
  file.directory:
    - name: /etc/wazuh-indexer/certs
    - user: wazuh-indexer
    - group: wazuh-indexer
    - mode: 500

unpack_wazuh_certs:
  cmd.run:
    - name: tar -xf ./wazuh-certificates.tar -C /etc/wazuh-indexer/certs/ ./{{ current_node.name }}.pem ./{{ current_node.name }}-key.pem ./admin.pem ./admin-key.pem ./root-ca.pem
    - runas: root
    - require:
      - cmd: generate_wazuh_certs
      - file: deploy_wazuh_certs_dir

# Set directory permissions
set_certs_dir_permissions:
    cmd.run:
    - name: chmod 500 /etc/wazuh-indexer/certs
    - runas: root
    - require:
      - cmd: unpack_wazuh_certs

# Set file permissions inside the directory
set_certs_file_permissions:
  cmd.run:
    - name: chmod 400 /etc/wazuh-indexer/certs/*
    - runas: root
    - require:
      - cmd: set_certs_dir_permissions

set_certs_folder_permission:
  cmd.run:
    - name: chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs
    - runas: root
    - require:
      - cmd: set_certs_file_permissions

# Manage the opensearch.yml config
/etc/wazuh-indexer/opensearch.yml:
  file.managed:
    - source: salt://wazuh/files/opensearch.yml.jinja
    - template: jinja
    - user: root
    - group: root
    - mode: 644
    - require:
      - pkg: wazuh-indexer-deps


reload_systemd_daemon:
  cmd.run:
    - name: systemctl daemon-reload
    - runas: root

enable_wazuh_indexer:
  service.enabled:
    - name: wazuh-indexer
    - require:
      - cmd: reload_systemd_daemon

start_wazuh_indexer:
  service.running:
    - name: wazuh-indexer
    - enable: True
    - require:
      - service: enable_wazuh_indexer

disable_update:
  cmd.run:
    - name: sed -i "s/^deb /#deb /" /etc/apt/sources.list.d/wazuh.list && apt update
    - runas: root
    - require:
      - cmd: reload_systemd_daemon

start_cluster:
  cmd.run:
    - name: /usr/share/wazuh-indexer/bin/indexer-security-init.sh
    - runas: root
    - require:
      - cmd: disable_update