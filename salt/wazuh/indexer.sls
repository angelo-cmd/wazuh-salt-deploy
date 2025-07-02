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

download_wazuh_tools:
  cmd.run:
    - name: curl -sO https://packages.wazuh.com/4.12/wazuh-certs-tool.sh
    - cwd: /root
    - creates: /root/wazuh-certs-tool.sh

/root/config.yml:
  file.managed:
    - source: salt://wazuh/files/config.yml.jinja
    - template: jinja
    - user: root
    - group: root
    - mode: 644

generate_wazuh_certs:
  cmd.run:
    - name: bash  /root/wazuh-certs-tool.sh -A
    - unless: test -f /root/wazuh-certificates/admin.pem
    - require:
      - file: /root/config.yml
  file.managed:
    - name: /root/wazuh-certificates.tar
    - source: salt://wazuh/files/wazuh-certificates.tar
    - mode: 644
    - user: root
    - group: root
    - unless: test -f /root/wazuh-certificates

compress_certificates:
  cmd.run:
    - name:  tar -cvf /root/wazuh-certificates.tar -C /root/wazuh-certificates/ .
    - require:
      - cmd: generate_wazuh_certs
mv_cert:
  cmd.run:
    - name: mv  /root/wazuh-certificates.tar /srv/salt/wazuh/files
    - unless: test -f /root/wazuh-certificates/admin.pem
    - require:
      - cmd: compress_certificates
wazuh_indexer_pkg:
  pkg.installed:
    - name: wazuh-indexer
    - require:
      - cmd: apt_update

deploy_wazuh_certs_dir:
  file.directory:
    - name: /etc/wazuh-indexer/certs
    - user: wazuh-indexer
    - group: wazuh-indexer
    - mode: 500

unpack_wazuh_certs:
  cmd.run:
    - name: tar -xf ./wazuh-certificates.tar -C /etc/wazuh-indexer/certs/ ./{{ ns.current_node.name }}.pem ./{{ ns.current_node.name }}-key.pem ./admin.pem ./admin-key.pem ./root-ca.pem
    - runas: root
    - require:
      - cmd: generate_wazuh_certs
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
