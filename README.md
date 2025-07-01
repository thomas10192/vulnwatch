## 🔒 Daily CVE Alert Script<br/>

This script retrieves recently published critical CVEs from the NVD API, filters them based on a vendor list, and sends a daily alert to Microsoft Teams, Slack or Discord.<br/>

## 📌 Features<br/>
Fetches CVEs published in the last 24 hours.<br/>

Filters for only CRITICAL severity vulnerabilities.<br/>

Checks if any predefined vendors are mentioned.<br/>

Sends an alert with relevant CVE details via a webhook.<br/>

Uses a cve list stored in an seen_cves.json to remove duplications.<br/>


## 📁 Project Structure <br/>
.<br/>
├── script.py                # Main script <br/>
├── seen_cves.json           # json file containing CVEs id<br/>
├── .env                     # Contains webhook url<br/>
├── nvdcve-1.1-recent.json   # Auto-generated file with recent CVEs used for testing<br/>
└── README.md                # You're reading this<br/>

## ⚙️ Requirements<br/>
Python 3.7+<br/>

Dependencies: <br/>
```
# You will need to install the packages requests, openpyxl and python-dotenv
pip install requests openpyxl python-dotenv
```

## 🛠️ Setup Instructions<br/>
Clone the repo or place the script and files in a directory.<br/>

Create a .env file in the same directory:<br/>

TEAMS_WEBHOOK=you_webbhook<br/>

## 🪝 Webhook Setup
 
── If you're using Slack, you can format the message using [Block Kit](https://api.slack.com/block-kit).<br/>

── For Microsoft Teams, use [Incoming Webhooks](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook).<br/>

## ✉️ Output<br/>
Prints matching CVEs in the console.<br/>

Sends an alert titled: Daily CVE Report.<br/>

If no matching CVEs are found, it sends an alert with: "No new CVEs for today!!!"<br/>

### ✅ Example aler Content<br/>

There are 2 CVEs to look at!<br/>

Relevant CVE: CVE-2025-XXXX<br/>
Published Date: 2025-06-27T15:23Z<br/>
Severity: CRITICAL<br/>
Base Score: 9.8<br/>
Vector: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H<br/>
Description: [Short description]<br/>
NVD Link: [NVD URL]<br/>
...<br/>


