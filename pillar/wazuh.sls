wazuh:
  nodes:
    indexer:
      - name: indexer
        ip: "10.0.22.11"
      # - name: node-2
      #   ip: "10.0.0.2"
      # - name: node-3
      #   ip: "10.0.0.3"
    server:
      - name: wazuh-1
        ip: "10.0.1.1"
        node_type: master
      - name: wazuh-2
        ip: "10.0.1.2"
        node_type: worker
      # - name: wazuh-3
      #   ip: "10.0.1.3"
      #   node_type: worker
    dashboard:
      - name: dashboard
        ip: "10.0.2.1"



