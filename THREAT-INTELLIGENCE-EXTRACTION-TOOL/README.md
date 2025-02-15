# 🛡️ Threat Intelligence Extraction Tool

*Automated PDF Analysis with MITRE ATT&CK Mapping & VirusTotal Integration*

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](https://opensource.org/licenses/MIT)


## 🎯 Features
- **PDF Text Extraction**: Multi-page report processing
- **IoC Detection**: IPs, Domains, Hashes, Emails
- **Threat Analysis**: 
  - MITRE ATT&CK TTP Mapping
  - Threat Actor Identification
  - Targeted Industry Detection
- **Malware Analysis**: VirusTotal integration
- **Custom Outputs**: Select specific data fields

## 💻 Installation

```bash
# Clone repository
git clone https://github.com/prajjwaltiwarii/THREAT-INTELLIGENCE-EXTRACTION-TOOL.git
cd THREAT-INTELLIGENCE-EXTRACTION-TOOL

# Install dependencies
pip install -r Requirements.txt
python -m spacy download en_core_web_sm
```
```
# For Windows

    Update Locale Settings (Windows):

        Go to Control Panel > Region > Administrative > Change system locale

        Check Beta: Use Unicode UTF-8 for worldwide language support

        Reboot your system.
or

    Use Linux/WSL:
    Linux handles Unicode better. Consider using Windows Subsystem for Linux (WSL).
```
```
# For Linux/Mac
- First You Have To Create a Virtual Enviorment in python to install all these dependencies 
```
## USAGE

 Basic Extraction
 ``` python script.py -i report.pdf```

 Full Analysis (with VirusTotal)
``` python script.py -i report.pdf -k YOUR_VT_API_KEY```

 Custom Output Fields
 ``` Get only IoCs and TTPs python```
 ``` script.py -i report.pdf -f iocs ttps ```

 Available Fields:
 ``` iocs = Indicators of Compromise ```
 ``` ttps = MITRE TTPs ```
 ``` threat_actors = Threat Actors```
 ``` malware = Malware Details```
 ``` targeted_entities = Targeted Organizations``` 

## 📄 Sample Output

```{
  "IoCs": {
    "IP_addresses": ["192.168.1.1"],
    "Domains": ["evil.com"],
    "Hashes": ["a1b2c3d4..."],
    "Emails": ["phish@evil.com"]
  },
  "TTPs": {
    "Tactics": [{"TA0001": "Initial Access"}],
    "Techniques": [{"T1566.001": "Spearphishing Attachment"}]
  },
  "Threat Actor(s)": ["APT29"],
  "Malware": [
    {
      "Name": "Shamoon",
      "md5": "a1b2c3...",
      "sha256": "d4e5f6...",
      "tags": ["wiper"]
    }
  ],
  "Targeted Entities": ["Energy Sector"]
}

```
## 🛠️ Troubleshooting

```
    Missing spaCy Model:
    python -m spacy download en_core_web_sm

    PDF Extraction Issues: Use simpler PDF layouts

    VirusTotal Errors: Check API quota here
```
