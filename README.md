# 👨🏻‍🔧👩🏻‍🔧 Security Monitoring Tool

## 📖 Description

This tool is designed to monitor the security of a network. 

It is able to detect and alert the user of any suspicious activity on the network. 

The tool is able to monitor the network in real-time and alert the user of any potential threats. 

The tool is also able to generate reports on the security of the network and provide recommendations on how to improve the security of the network.


## 🌟 Features

- Real-time monitoring of the network
- Detection of suspicious activity
- Alerting the user of potential threats
- Generating reports on the security of the network


## ⚙️ Requirements

- Python 3.6 or higher
- AbuseIPDB API key


## 🚀 Run the tool

Export the API key as an environment variable:

```
export ABUSEIPDB_API_KEY=<your_api_key>
```

Install the required packages:

```
pip install -r requirements.txt
```

Run the tool:

```
python security_check.py
```

After running the tool, you will see the following output:

```
Checking for suspicious activity...
No suspicious activity detected.
```

Logs will be written to the `/var/log/security_monitor/` directory.

## 🆘 TODO

- Add support for more threat intelligence feeds (e.g. VirusTotal, Shodan)
- Add support for more security checks (e.g. open ports, weak passwords)
- Add support for more alerting mechanisms (e.g. email, SMS)
- Add support for more reporting options (e.g. PDF, CSV)
- Add support for more configuration options (e.g. scan frequency, alert threshold)
