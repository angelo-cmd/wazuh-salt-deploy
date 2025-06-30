{% set wazuh_key = 'da settare' %}
{% set current_ip = salt['cmd.run']('hostname -i').split()[0] %}
{% set wazuh_indexer_nodes = pillar.get('wazuh', {}).get('nodes', {}).get('indexer', []) %}
{% set indexer_hosts = [] %}
{% for node in wazuh_indexer_nodes %}
  {% do indexer_hosts.append(node.ip ~ ':9200') %}
{% endfor %}
{# Determine master node #}
{% set master_node = None %}
{% for node in wazuh_server_nodes %}
  {% if node.get('node_type') == 'master' %}
    {% set master_node = node %}
    {% break %}
  {% endif %}
{% endfor %}

{# Determine master node #}
{% set current_node = None %}
{% for node in wazuh_server_nodes %}
  {% if node is defined and node.ip == current_ip%}
    {% set current_node = node %}
    {% break %}
  {% endif %}
{% endfor %}

{% set hosts_block = "" %}
{% for node in wazuh_indexer_nodes %}
  {% set hosts_block = hosts_block + "    <host>https://" + node.ip + ":9200</host>\n" %}
{% endfor %}

# Ensure dependencies are installed
wazuh-master-deps:
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
    - unless: test -f /root/wazuh-certs-tool.sh
    - cwd: /root
    - creates: /root/wazuh-certs-tool.sh



# Install Wazuh Manager
wazuh_master_pkg:
  pkg.installed:
    - name: wazuh-manager
    - require:
      - cmd: apt_update

# Install Filebeat
wazuh_filebeat_pkg:
  pkg.installed:
    - name: filebeat
    - require:
      - cmd: apt_update

# Download Filebeat configuration
wazuh_filebeat_files:
  cmd.run:
    - name: curl -so /etc/filebeat/filebeat.yml https://packages.wazuh.com/4.12/tpl/wazuh/filebeat/filebeat.yml
    - require:
      - pkg: wazuh_filebeat_pkg

# Configure Filebeat hosts
replace_filebeat_hosts:
  file.replace:
    - name: /etc/filebeat/filebeat.yml
    - pattern: '^ *hosts:.*'
    - repl: '  hosts: [{{ indexer_hosts | map("tojson") | join(", ") }}]'
    - require:
      - cmd: wazuh_filebeat_files


# Ensure Filebeat keystore exists
create_filebeat_keystore:
  cmd.run:
    - name: filebeat keystore create
    - unless: test -f /etc/filebeat/filebeat.keystore
    - require:
      - pkg: wazuh_filebeat_pkg

# Add username to keystore
add_filebeat_username:
  cmd.run:
    - name: echo admin | filebeat keystore add username --stdin --force
    - require:
      - cmd: create_filebeat_keystore

# Add password to keystore
add_filebeat_password:
  cmd.run:
    - name: echo admin | filebeat keystore add password --stdin --force
    - require:
      - cmd: create_filebeat_keystore

# Download Wazuh indexer template
download_wazuh_template:
  cmd.run:
    - name: curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/v4.12.0/extensions/elasticsearch/7.x/wazuh-template.json
    - unless: test -f /etc/filebeat/wazuh-template.json
    - require:
      - pkg: wazuh_filebeat_pkg

# Set permissions on template
chmod_wazuh_template:
  cmd.run:
    - name: chmod go+r /etc/filebeat/wazuh-template.json
    - require:
      - cmd: download_wazuh_template

# Install Wazuh Filebeat module
install_wazuh_filebeat_module:
  cmd.run:
    - name: curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.4.tar.gz | tar -xvz -C /usr/share/filebeat/module
    - unless: test -d /usr/share/filebeat/module/wazuh
    - require:
      - pkg: wazuh_filebeat_pkg

# Ensure target cert dir exists
deploy_wazuh_certs_dir:
  file.directory:
    - name: /etc/filebeat/certs
    - user: root
    - group: root
    - mode: 500

# Unpack certificates
unpack_wazuh_certs:
  cmd.run:
    - name: tar -xf /root/wazuh-certificates.tar -C /etc/filebeat/certs/ ./{{ current_node.name }}.pem ./{{ current_node.name }}-key.pem ./admin.pem ./admin-key.pem ./root-ca.pem
    - runas: root
    - require:
      - file: deploy_wazuh_certs_dir

# Rename certificate files
rename_filebeat_cert:
  cmd.run:
    - name: mv -n /etc/filebeat/certs/{{ current_node.name }}.pem /etc/filebeat/certs/filebeat.pem
    - unless: test -f /etc/filebeat/certs/filebeat.pem
    - require:
      - cmd: unpack_wazuh_certs

rename_filebeat_key:
  cmd.run:
    - name: mv -n /etc/filebeat/certs/{{ current_node.name }}-key.pem /etc/filebeat/certs/filebeat-key.pem
    - unless: test -f /etc/filebeat/certs/filebeat-key.pem
    - require:
      - cmd: unpack_wazuh_certs

# Set certificate permissions
set_certs_dir_permissions:
  cmd.run:
    - name: chmod 500 /etc/filebeat/certs
    - runas: root
    - require:
      - cmd: rename_filebeat_cert
      - cmd: rename_filebeat_key

set_certs_file_permissions:
  cmd.run:
    - name: chmod 400 /etc/filebeat/certs/*
    - runas: root
    - require:
      - cmd: set_certs_dir_permissions

set_certs_folder_permission:
  cmd.run:
    - name: chown -R root:root /etc/filebeat/certs
    - runas: root
    - require:
      - cmd: set_certs_file_permissions

# Update Wazuh Manager configuration
update_ossec_indexer_hosts_block:
  file.blockreplace:
    - name: /var/ossec/etc/ossec.conf
    - marker_start: "<!-- SALT-MANAGED-START: INDEXER HOSTS -->"
    - marker_end: "<!-- SALT-MANAGED-END: INDEXER HOSTS -->"
    - content: |
        <hosts>
{{ hosts_block | indent(10, true) }}        </hosts>
    - append_if_not_found: True
    - require:
      - pkg: wazuh_master_pkg

# Reload systemd daemon
reload_systemd_daemon:
  cmd.run:
    - name: systemctl daemon-reload
    - runas: root

# Enable and start Wazuh Manager
wazuh-manager:
  service.running:
    - enable: True
    - require:
      - pkg: wazuh_master_pkg
      - cmd: reload_systemd_daemon
      - file: update_ossec_indexer_hosts_block

# Enable and start Filebeat
filebeat:
  service.running:
    - enable: True
    - require:
      - pkg: wazuh_filebeat_pkg
      - cmd: wazuh_filebeat_files
      - file: replace_filebeat_hosts
      - cmd: create_filebeat_keystore
      - cmd: add_filebeat_username
      - cmd: add_filebeat_password
      - cmd: download_wazuh_template
      - cmd: chmod_wazuh_template
      - cmd: install_wazuh_filebeat_module
      - cmd: set_certs_folder_permission

# Disable Wazuh repository updates
disable_update:
  cmd.run:
    - name: sed -i "s/^deb /#deb /" /etc/apt/sources.list.d/wazuh.list && apt update
    - runas: root
    - require:
      - service: wazuh-manager
      - service: filebeat
{% if master_node is not none and current_node.name == node_name %}
wazuh_cluster_config:
  file.blockreplace:
    - name: /var/ossec/etc/ossec.conf
    - marker_start: '<cluster>'
    - marker_end: '</cluster>'
    - content: |
        <cluster>
          <name>wazuh</name>
          <node_name>{{ master_node.name }}</node_name>
          <key>{{ wazuh_key }}</key>
          <node_type>master</node_type>
          <port>1516</port>
          <bind_addr>{{ current_node.ip }}</bind_addr>
          <nodes>
            <node>{{ master_node.name }}</node>
          </nodes>
          <hidden>no</hidden>
          <disabled>no</disabled>
        </cluster>
    - append_if_not_found: True
    - backup: True
{% endif %}
