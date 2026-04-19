# NetScaler Dashboard — Ultimate Edition

A modern, production-ready Flask dashboard for NetScaler with **parallel support** for both **NITRO API** and the **Next-Gen API**.  
The app automatically detects which API is supported per node and **falls back to NITRO** when Next-Gen is unavailable.

This project is fully containerized using **Docker** and runs behind **Gunicorn** for optimal production performance.

---

## Key Features

- **Production Ready:** Fully dockerized with `docker-compose` and Gunicorn WSGI.
- **Dual-Stack Runtime:** Auto-detects Next-Gen API support per node; seamless fallback to NITRO.
- **Dynamic HA State Tracking:** Continuously monitors and logs NetScaler High Availability (HA) state changes (Primary/Secondary) natively.
- **UI-Driven Configuration:** Easily configure NetScaler IP addresses, ports, protocols, and credentials directly from the Dashboard Settings modal (no need to restart the server).
- **Client-Side Exports:** Instantly export table data (Failover History, User Sessions) to **Excel** or **PDF** without server overhead.
- **License & Capacity Visibility:** Displays node license edition (Standard, Advanced, Premium), mode, and allocated bandwidth.
- **Unsaved Configuration Alerts:** Automatically alerts you with an orange banner if the Primary NetScaler has unsaved running configurations.
- **Timezone Aware:** Fully synchronized to Israel Standard Time (IDT/IST) using `pytz`.
- **Unlock Users:** Quickly unlock AAA users directly from the UI.

---

## Project Structure

```text```
netscaler-dashboard/
├── app.py                      # Main Flask application
├── requirements.txt            # Python dependencies
├── .env                        # Environment variables (App secrets)
├── Dockerfile                  # Docker image blueprint
├── docker-compose.yml          # Container orchestration
├── .gitignore                  # Git ignore rules
├── .dockerignore               # Docker ignore rules
├── LICENSE                     # License file
├── auth_config.json            # Local dashboard admin credentials
├── nodes_config.json           # NetScaler nodes configuration (UI managed)
├── failover_history.json       # Persistent HA state history
├── ha_last_state.json          # Last known HA state tracker
├── netscaler_complete.log      # Application logs
├── static/                     # Static assets
│   ├── netscaler_logo.png
│   └── netscaler_icon.ico
└── templates/                  # HTML Templates
    ├── dashboard.html
    ├── login.html
    └── change_password.html

Install & Run (Production via Docker)
The recommended way to run this application is using Docker and Docker Compose. This ensures the app runs consistently with Gunicorn.
1. Clone the repository:
   ```Bash```
   git clone <your-repo-url>
   cd netscaler-dashboard
2. Configure App Secrets:
Create a .env file in the root directory for Flask/App secrets. (NetScaler node IPs and passwords are now configured directly from the UI).
3. Build and Run:
  ```Bash```
  docker-compose up -d --build
4. Access the Dashboard:
Open your browser and navigate to http://<your-server-ip>:5000

Local Development (Without Docker)
If you wish to run the app locally for development purposes:

1. Install dependencies:
  ```Bash```
  pip install -r requirements.txt
2. Start the Flask development server:
  ```Bash```
  python app.py
Using the Dashboard
⚙️ Initial Setup (Settings)
On your first login, click the Settings (gear) icon in the top right. Enter your Primary and Secondary NetScaler IPs, ports, protocols (HTTP/HTTPS), and credentials. Click Save & Apply. The app will immediately detect node capabilities.

📊 Overview Tab
System Stats: Live CPU, Memory, and HTTP request rates.

Node Statistics: Real-time IP, firmware version, and HA role.

License & Capacity: Displays the allocated bandwidth and license edition.

HA Status: Shows sync status and peer states.

Unsaved Config Warning: An orange banner will appear if the primary node has unsaved changes.

🌐 Applications & Services
Next-Gen Mode: Displays native Next-Gen Applications.

NITRO Mode: Displays Load Balancing vServers and active Services / Service Groups.

🔄 Failover History
The dashboard actively tracks role transitions.

Filter historical failovers using a custom date-picker (defaults to the last 24 hours).

Export exactly what you see to Excel or PDF.

👥 User Sessions
View active AAA and VPN sessions.

Filter by User, Type (Web/VPN), and Status.

Export results to Excel or PDF.

🔓 Unlock Users
Select the relevant node (Primary/Secondary).

Type the username and instantly release account lockouts.

Security & Best Practices
Never commit .env or *.json files: Passwords, hashes, and node configurations are stored in nodes_config.json and auth_config.json. Ensure they are ignored via .gitignore.

Docker Volumes: The docker-compose.yml file uses volumes to ensure your JSON databases and configurations survive container restarts.

Admin Password: The default dashboard login is admin / admin. You will be prompted to change this upon your first login.

License
This project is licensed under the terms specified in the LICENSE file.
