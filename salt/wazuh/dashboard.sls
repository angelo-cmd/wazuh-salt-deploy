{# -------------------- JINJA SECTION -------------------- #}

{# Load nodes from pillars safely #}
{% set wazuh_indexer_nodes = pillar.get('wazuh', {}).get('nodes', {}).get('indexer', []) %}
{% set wazuh_server_nodes = pillar.get('wazuh', {}).get('nodes', {}).get('server', []) %}
{% set wazuh_dash_nodes = pillar.get('wazuh', {}).get('nodes', {}).get('dashboard', []) %}

{# Determine master node #}
{% set master_node = None %}
{% for node in wazuh_server_nodes %}
  {% if node.get('node_type') == 'master' %}
    {% set master_node = node %}
    {% break %}
  {% endif %}
{% endfor %}

{% if not master_node and wazuh_server_nodes %}
  {% set master_node = wazuh_server_nodes[0] %}
{% endif %}

{# Set dashboard node details (assuming single-node) #}
{% if wazuh_dash_nodes %}
  {% set dashboard_node = wazuh_dash_nodes[0] %}
  {% set node_name = dashboard_node.name %}
  {% set node_ip = dashboard_node.ip %}
{% else %}
  {% set node_name = 'dashboard' %}
  {% set node_ip = '127.0.0.1' %}
{% endif %}

{# Format list of indexer hosts #}
{% set indexer_hosts = [] %}
{% for node in wazuh_indexer_nodes %}
  {% do indexer_hosts.append('https://' ~ node.ip ~ ':9200') %}
{% endfor %}

{# Optional block for XML-style config #}
{% set hosts_block = "" %}
{% for node in wazuh_indexer_nodes %}
  {% set hosts_block = hosts_block + "    <host>https://" + node.ip + ":9200</host>\n" %}
{% endfor %}


# -------------------- SALT SECTION --------------------

wazuh-master-deps:
  pkg.installed:
    - pkgs:
      - coreutils
      - curl
      - apt-transport-https
      - tar
      - debhelper 
      - libcap2-bin


wazuh_gpg_key:
  cmd.run:
    - name: >
        curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH |
        gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import &&
        chmod 644 /usr/share/keyrings/wazuh.gpg
    - unless: test -f /usr/share/keyrings/wazuh.gpg

wazuh_apt_repo:
  cmd.run:
    - name: echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' >> /etc/apt/sources.list.d/wazuh.list
    - unless: grep -q '^deb .*packages.wazuh.com.* stable main' /etc/apt/sources.list.d/wazuh.list
    - require:
      - cmd: wazuh_gpg_key


apt_update:
  cmd.run:
    - name: apt-get update
    - require:
      - cmd: wazuh_apt_repo

wazuh_dashboard_pkg:
  pkg.installed:
    - name: wazuh-dashboard
    - require:
      - cmd: apt_update

replace_opensearch_dashboard:
  file.replace:
    - name: /etc/wazuh-dashboard/opensearch_dashboards.yml
    - pattern: 'server.host:.*'
    - repl: 'server.host: {{ node_ip }}'
    - require:
      - pkg: wazuh_dashboard_pkg

replace_opensearch_dashboard_hosts:
  file.replace:
    - name: /etc/wazuh-dashboard/opensearch_dashboards.yml
    - pattern: 'opensearch.hosts:.*'
    - repl: 'opensearch.hosts: [{{ indexer_hosts | map("tojson") | join(", ") }}]'
    - require:
      - pkg: wazuh_dashboard_pkg

# Ensure target cert dir exists
deploy_wazuh_certs_dir:
  file.directory:
    - name: /etc/wazuh-dashboard/certs
    - user: root
    - group: root
    - mode: 500
unpack_wazuh_certs:
  cmd.run:
    - name: tar -xf /root/wazuh-certificates.tar -C /etc/wazuh-dashboard/certs/ ./{{ node_name }}.pem ./{{ node_name }}-key.pem ./admin.pem ./admin-key.pem ./root-ca.pem
    - runas: root
    - require:
      - file: replace_opensearch_dashboard_hosts

rename_dashboard_cert:
  cmd.run:
    - name: mv -n /etc/wazuh-dashboard/certs/{{ node_name }}.pem /etc/wazuh-dashboard/certs/dashboard.pem
    - unless: test -f /etc/wazuh-dashboard/certs/dashboard.pem
    - require:
      - cmd: unpack_wazuh_certs

rename_dashboard_key:
  cmd.run:
    - name: mv -n /etc/wazuh-dashboard/certs/{{ node_name }}-key.pem /etc/wazuh-dashboard/certs/dashboard-key.pem
    - unless: test -f /etc/wazuh-dashboard/certs/dashboard-key.pem
    - require:
      - cmd: rename_dashboard_cert

set_certs_dir_permissions:
  cmd.run:
    - name: chmod 500 /etc/wazuh-dashboard/certs
    - runas: root
    - require:
      - cmd: rename_dashboard_cert
      - cmd: rename_dashboard_key

set_certs_file_permissions:
  cmd.run:
    - name: chmod 400 /etc/wazuh-dashboard/certs/*
    - runas: root
    - require:
      - cmd: set_certs_dir_permissions

set_certs_folder_permission:
  cmd.run:
    - name: chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs
    - runas: root
    - require:
      - cmd: set_certs_file_permissions
reload_systemd_daemon:
  cmd.run:
    - name: systemctl daemon-reload
    - runas: root
    - require:
        - cmd: set_certs_folder_permission

wazuh-dashboard:
  service.running:
    - enable: True
    - require:
      - cmd: reload_systemd_daemon

enable_wazuh_dashboard:
  service.running:
    - name: wazuh-dashboard
    - enable: true

sleep-before-association:
  cmd.run:
    - name: sleep 10

replace_wazuh_dashboard_url:
  file.replace:
    - name: /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
    - pattern: '<WAZUH_SERVER_IP_ADDRESS>'
    - repl: '{{ master_node.ip }}'
    - require:
      - pkg: wazuh_dashboard_pkg
      - cmd: sleep-before-association

# Disable Wazuh repository updates
disable_update:
  cmd.run:
    - name: sed -i "s/^deb /#deb /" /etc/apt/sources.list.d/wazuh.list && apt update
    - runas: root
    - require:
      - file: replace_wazuh_dashboard_url