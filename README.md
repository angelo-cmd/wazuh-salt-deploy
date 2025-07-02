# WAZUH-SALT-DEPLOY

This repository provides SaltStack configurations and states to deploy a Wazuh cluster using a Salt master-minion architecture.

---

## 📁 Project Structure

```
WAZUH-SALT-DEPLOY/
├── pillar/
│   ├── top.sls
│   └── wazuh.sls                  # Wazuh pillar configuration
├── salt/
│   └── wazuh/
│       ├── files/
│       │   ├── config.yml.jinja
│       │   └── opensearch.yml.jinja
│       ├── dashboard.sls         # Deploys the Wazuh dashboard
│       ├── indexer.sls           # Deploys the Wazuh indexer
│       ├── manager.sls           # Deploys the Wazuh manager
│       └── top.sls
```

---

## 🧰 Prerequisites

- Install **Salt Master** on the machine hosting this repository.
- Install **Salt Minions** on the target machines where Wazuh components will be deployed.

---

## ⚙️ Minion Configuration

On each **minion**, edit the Salt config file (usually `/etc/salt/minion`):

```yaml
#master: salt          # Replace or uncomment this line
master: <IP_OF_SALT_MASTER>

port: 4506             # Make sure this line is uncommented

id: <custom-minion-id> # (Optional) Set custom ID for the minion
```

Restart the Salt services:

```bash
sudo systemctl restart salt-minion
```

On the master:

```bash
sudo systemctl restart salt-master
sudo salt-key -L       # List unaccepted keys
sudo salt-key -A       # Accept all keys
```

---

## 🚀 Deployment Steps

1. **Edit the Wazuh pillar file on the master:**

   ```bash
   sudo nano /srv/pillar/wazuh.sls
   ```

2. **Deploy the Indexer (locally on master):**

   ```bash
   sudo salt-call --local state.apply wazuh.indexer
   ```

3. **Deploy the Wazuh Manager (on the minion that acts as master):**

   Make sure the `top.sls` file targets the correct minion ID:

   ```bash
   sudo salt '<minion-id>' state.apply
   ```

4. **Deploy the Dashboard (on another minion or same):**

   ```bash
   sudo salt '<minion-id>' state.apply
   ```

---

## 🔐 Cluster Configuration

- For cluster deployment, set the **key exchange value** in `manager.sls`.
- Ensure `config.yml.jinja` has correct values via the pillar (`wazuh.sls`).

---

## 🔑 Default Login

After deployment, access the Wazuh dashboard:

- **Username:** `admin`
- **Password:** `admin`

Change the password after logging in.

---

## 🛠 Troubleshooting

- If the cluster isn't running, review configs for errors.
- Restart Wazuh components:

  ```bash
  sudo systemctl restart wazuh-manager
  sudo systemctl restart wazuh-indexer
  sudo systemctl restart wazuh-dashboard
  ```

---

## ➕ Adding More Components

To add additional workers or indexers:

- Add new minions.
- Target them with:

  ```bash
  sudo salt '<new-minion-id>' state.apply wazuh.indexer
  sudo salt '<new-minion-id>' state.apply wazuh.manager
  ```

---

## 🔗 Further Steps

- Visit [Wazuh Documentation](https://documentation.wazuh.com/) to:
  - Set a secure password.
  - Validate the health of the cluster.
  - Explore advanced deployments and customizations.
