{% set wazuh_indexer_nodes = pillar.get('wazuh', {}).get('nodes', {}).get('indexer', []) %}
{% set ns = namespace(current_node=None) %}
{% set current_ip = salt['cmd.run']('hostname -I').split()[0] %}

{% do salt.log.info("Current IP: " ~ current_ip) %}

{% for node in wazuh_indexer_nodes %}
  {% do salt.log.info("Checking node: " ~ node.get('name', 'no-name') ~ ", IP: " ~ node.get('ip', 'no-ip')) %}
  {% if node.get('ip') == current_ip %}
    {% set ns.current_node = node %}
    {% do salt.log.info("Matched current node: " ~ node.get('name')) %}
  {% endif %}
{% endfor %}

{% if not ns.current_node %}
  {{ raise("No matching indexer node found for current IP: " ~ current_ip) }}
{% endif %}

{% do salt.log.info("Matched node name: " ~ ns.current_node.name) %}

wazuh-indexer-deps:
  pkg.installed:
    - pkgs:
      - coreutils
      - curl
      - apt-transport-https

wazuh_gpg_key:
  cmd.run:
    - name: >
        curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH |
        gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import &&
        chmod 644 /usr/share/keyrings/wazuh.gpg
    - unless: test -f /usr/share/keyrings/wazuh.gpg

wazuh_apt_repo:
  file.append:
    - name: /etc/apt/sources.list.d/wazuh.list
    - text: 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main'
    - require:
      - cmd: wazuh_gpg_key

apt_update:
  cmd.run:
    - name: apt-get update
    - require:
      - file: wazuh_apt_repo

# Step 1: Try to get certificates from salt master
deploy_existing_certificates:
  file.managed:
    - name: /root/wazuh-certificates.tar
    - source: salt://wazuh/files/wazuh-certificates.tar
    - mode: 644
    - user: root
    - group: root
    - failhard: False

# Step 2: If no certificates exist, generate them
download_wazuh_tools:
  cmd.run:
    - name: curl -sO https://packages.wazuh.com/4.12/wazuh-certs-tool.sh
    - cwd: /root
    - creates: /root/wazuh-certs-tool.sh
    - onlyif: "test ! -f /root/wazuh-certificates.tar"  # Esegue solo se i certificati NON esistono

create_config_yml:
  file.managed:
    - name: /root/config.yml
    - source: salt://wazuh/files/config.yml.jinja
    - template: jinja
    - user: root
    - group: root
    - mode: 644
    - require:
      - cmd: download_wazuh_tools

generate_certificates:
  cmd.run:
    - name: bash /root/wazuh-certs-tool.sh -A
    - cwd: /root
    - require:
      - file: create_config_yml

compress_certificates:
  cmd.run:
    - name: tar -cvf /root/wazuh-certificates.tar -C /root/wazuh-certificates/ .
    - cwd: /root
    - unless: test -f /root/wazuh-certificates.tar
    - require:
      - cmd: generate_certificates



# Step 4: Install wazuh-indexer
wazuh_indexer_pkg:
  pkg.installed:
    - name: wazuh-indexer
    - require:
      - cmd: apt_update

# Step 5: Deploy certificates to indexer
deploy_wazuh_certs_dir:
  file.directory:
    - name: /etc/wazuh-indexer/certs
    - user: wazuh-indexer
    - group: wazuh-indexer
    - mode: 500
    - require:
      - pkg: wazuh_indexer_pkg



unpack_wazuh_certs:
  cmd.run:
    - name: tar -xf /root/wazuh-certificates.tar -C /etc/wazuh-indexer/certs/ ./{{ ns.current_node.name }}.pem ./{{ ns.current_node.name }}-key.pem ./admin.pem ./admin-key.pem ./root-ca.pem
    - cwd: /root
    - runas: root
    - require:
      - file: deploy_wazuh_certs_dir

set_certs_dir_permissions:
  cmd.run:
    - name: chmod 500 /etc/wazuh-indexer/certs
    - runas: root
    - require:
      - cmd: unpack_wazuh_certs

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

/etc/wazuh-indexer/opensearch.yml:
  file.managed:
    - source: salt://wazuh/files/opensearch.yml.jinja
    - template: jinja
    - user: root
    - group: root
    - mode: 644
    - require:
      - pkg: wazuh_indexer_pkg

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
      - file: /etc/wazuh-indexer/opensearch.yml
      - cmd: set_certs_folder_permission

disable_update:cd
  cmd.run:
    - name: sed -i "s/^deb /#deb /" /etc/apt/sources.list.d/wazuh.list
    - runas: root
    - require:
      - service: start_wazuh_indexer

start_cluster:
  cmd.run:
    - name: /usr/share/wazuh-indexer/bin/indexer-security-init.sh
    - runas: root
    - require:
      - cmd: disable_update