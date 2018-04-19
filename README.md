# SecBuddy
Project which interacts with Burp Suite API - A DevSecOps Project

# About
This project uses burp suite API to perform operations such as :
- Spidering 
- Active Scanning 
- Reporting in HTML

# Requirements
- burp-rest-api : https://github.com/vmware/burp-rest-api
- Burp Suite Professional

# Installation 
`pip install PyBurprestapi`

# Usage
Example 
`python main.py http://127.0.0.1  -t http://localhost -aP 8090` 

Option:
 `proxy_url : http://127.0.0.1` (Change this to your server address if you are running burp on another machine)
`-t : target url to be scanned` 
`-aP : API port` 


