wazuh:
  nodes:
    indexer:
      - name: indexer
        ip: "192.168.7.17"
      - name: indexer-2
        ip: "192.168.7.14"
      # - name: node-3
      #   ip: "10.0.0.3"
    server:
      - name: master
        ip: "192.168.7.12"
        node_type: master
      - name: worker
        ip: "192.168.7.13"
        node_type: worker
      # - name: wazuh-3
      #   ip: "10.0.1.3"
      #   node_type: worker
    dashboard:
      - name: dashboard
        ip: "192.168.7.17"



