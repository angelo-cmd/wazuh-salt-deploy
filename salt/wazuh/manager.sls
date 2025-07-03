{% set wazuh_key = pillar.get('wazuh_cluster_key')%}
{% set ns = namespace(current_node=None) %}
{% set ns = namespace(master_nodeter=None) %}
{% set current_ip = salt['cmd.run']('hostname -I').split()[0] %}
{% set wazuh_indexer_nodes = pillar.get('wazuh', {}).get('nodes', {}).get('indexer', []) %}
{% set wazuh_server_nodes = pillar.get('wazuh', {}).get('nodes', {}).get('server', []) %}

{% set indexer_hosts = [] %}
{% for node in wazuh_indexer_nodes %}
  {% do indexer_hosts.append(node.ip ~ ':9200') %}
{% endfor %}
{# Determine master node #}
{% for node in wazuh_server_nodes %}
  {% if node.get('node_type') == 'master' %}
    {% set ns.master_node = node %}
    {% break %}
  {% endif %}
{% endfor %}

{# Determine master node #}
{% for node in wazuh_server_nodes %}
  {% if node is defined and node.ip == current_ip%}
    {% set ns.current_node = node %}
    {% break %}
  {% endif %}
{% endfor %}

{% set hosts_block = "" %}
{% for node in wazuh_indexer_nodes %}
  {% set hosts_block = hosts_block + "    <host>https://" + node.ip + ":9200</host>\n" %}
{% endfor %}
{% do salt.log.info("hosts" ~ hosts_block) %}

# Ensure dependencies are installed
wazuh-master-deps:
  pkg.installed:
    - pkgs:
      - coreutils
      - curl
      - apt-transport-https


wazuh_certificates:
  file.managed:
    - name: /root/wazuh-certificates.tar
    - source: salt://wazuh/files/wazuh-certificates.tar
    - mode: 644
    - user: root
    - group: root
    - unless: test -f /root/wazuh-certificates.tar


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
#download_wazuh_tools:
#  cmd.run:
#    - name: curl -sO https://packages.wazuh.com/4.12/wazuh-certs-tool.sh
#    - unless: test -f /root/wazuh-certs-tool.sh
#    - cwd: /root
#    - creates: /root/wazuh-certs-tool.sh



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
    - name: filebeat keystore create --force
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
    - name: tar -xf /root/wazuh-certificates.tar -C /etc/filebeat/certs/ ./{{ ns.current_node.name }}.pem ./{{ ns.current_node.name }}-key.pem ./admin.pem ./admin-key.pem ./root-ca.pem
    - runas: root
    - require:
      - file: deploy_wazuh_certs_dir

# Rename certificate files
rename_filebeat_cert:
  cmd.run:
    - name: mv -n /etc/filebeat/certs/{{ ns.current_node.name }}.pem /etc/filebeat/certs/filebeat.pem
    - unless: test -f /etc/filebeat/certs/filebeat.pem
    - require:
      - cmd: unpack_wazuh_certs

rename_filebeat_key:
  cmd.run:
    - name: mv -n /etc/filebeat/certs/{{ ns.current_node.name }}-key.pem /etc/filebeat/certs/filebeat-key.pem
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

test_replace_indexer_host:
  file.replace:
    - name: /var/ossec/etc/ossec.conf
    - pattern: '<host>https://0\.0\.0\.0:9200</host>'
    - repl: |
        {% for node in wazuh_indexer_nodes %}
            <host>https://{{ node.ip }}:9200</host>
        {% endfor %}
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
      - file: test_replace_indexer_host

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
{% if ns.master_node is not none and ns.current_node.get('node_type') in ['master', 'worker'] %}
wazuh_cluster_config:
  file.blockreplace:
    - name: /var/ossec/etc/ossec.conf
    - marker_start: '<cluster>'
    - marker_end: '</cluster>'
    - content: |
         <name>wazuh</name>
          <node_name>{{ ns.current_node.name }}</node_name>
          <key>{{ wazuh_key }}</key>
          <node_type>{{ ns.current_node.node_type }}</node_type>
          <port>1516</port>
          <bind_addr>{{ ns.current_node.ip }}</bind_addr>
          <nodes>
            <node>{{ ns.master_node.ip }}</node>
          </nodes>
          <hidden>no</hidden>
          <disabled>no</disabled>
    - append_if_not_found: false
    - backup: True
{% endif %}
{% if ns.master_node is not none and ns.current_node.get('node_type') == 'master' %}

# Enable logall and logall_json
{% for tag in ['logall', 'logall_json'] %}
wazuh_enable_{{ tag }}:
  file.replace:
    - name: /var/ossec/etc/ossec.conf
    - pattern: '<{{ tag }}>no</{{ tag }}>'
    - repl: '<{{ tag }}>yes</{{ tag }}>'
    - backup: True
{% endfor %}

# Enable password auth (fix pattern: currently replaces no→no, should be no→yes)
wazuh_activate_agent_pwd:
  file.replace:
    - name: /var/ossec/etc/ossec.conf
    - pattern: '<use_password>no</use_password>'
    - repl: '<use_password>yes</use_password>'
    - backup: True

# Enable filebeat archives
filebeat_archives_enable:
  file.replace:
    - name: /etc/filebeat/filebeat.yml
    - pattern: 'archives:\s*\n\s*enabled:\s*false'
    - repl: |
        archives:
          enabled: true
    - backup: True

# Generate random password if missing
generate_authd_password_openssl:
  cmd.run:
    - name: openssl rand -base64 18 | cut -c1-18 > /var/ossec/etc/authd.pass
    - unless: test -f /var/ossec/etc/authd.pass

fix_authd_permissions:
  file.managed:
    - name: /var/ossec/etc/authd.pass
    - mode: 640
    - user: root
    - group: wazuh

# Restart wazuh-manager if config changed
wazuh_manager_restart:
  service.running:
    - name: wazuh-manager
    - enable: True
    - watch:
      - file: wazuh_enable_logall
      - file: wazuh_enable_logall_json
      - file: wazuh_activate_agent_pwd

# Restart filebeat if config changed
filebeat_service_restart:
  service.running:
    - name: filebeat
    - enable: True
    - watch:
      - file: filebeat_archives_enable

{% endif %}
