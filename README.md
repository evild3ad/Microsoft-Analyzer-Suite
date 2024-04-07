<img src="https://img.shields.io/badge/Language-Powershell-blue"> <a href="https://github.com/evild3ad/Microsoft-Analyzer-Suite/wiki"><img src="https://img.shields.io/badge/Wiki-Documentation-blue"></a> <img src="https://img.shields.io/badge/Maintenance%20Level-Actively%20Developed-brightgreen"> <a href="https://twitter.com/Evild3ad79"><img src="https://img.shields.io/twitter/follow/Evild3ad79?style=social"></a> <a href="https://twitter.com/InvictusIR"><img src="https://img.shields.io/twitter/follow/InvictusIR?style=social"></a>

# Microsoft-Analyzer-Suite (Community Edition)
A collection of PowerShell scripts for analyzing data from Microsoft 365 and Microsoft Entra ID.

## TL;DR  
Automated Processing of Microsoft 365 Logs and Microsoft Entra ID Logs extracted by [Microsoft-Extractor-Suite](https://github.com/invictus-ir/Microsoft-Extractor-Suite).

## The following Microsoft data sources are supported yet:

> Output Files of Microsoft-Extractor-Suite v1.3.2 by Invictus-IR

  * [Get-ADSignInLogsGraph](https://microsoft-365-extractor-suite.readthedocs.io/en/latest/functionality/AzureSignInLogsGraph.html) &#8594; [ADSignInLogsGraph-Analyzer v0.1](https://github.com/evild3ad/Microsoft-Analyzer-Suite/wiki/ADSignInLogsGraph%E2%80%90Analyzer)  
  * [Get-MFA](https://microsoft-365-extractor-suite.readthedocs.io/en/latest/functionality/GetUserInfo.html#retrieves-mfa-status) &#8594; [MFA-Analyzer v0.1](https://github.com/evild3ad/Microsoft-Analyzer-Suite/wiki/MFA%E2%80%90Analyzer)
  * [Get-RiskyDetections](https://microsoft-365-extractor-suite.readthedocs.io/en/latest/functionality/GetUserInfo.html#retrieves-the-risky-detections) &#8594; [RiskyDetections-Analyzer v0.2](https://github.com/evild3ad/Microsoft-Analyzer-Suite/wiki/RiskyDetections%E2%80%90Analyzer)
  * [Get-RiskyUsers](https://microsoft-365-extractor-suite.readthedocs.io/en/latest/functionality/GetUserInfo.html#retrieves-the-risky-users) &#8594; [RiskyUsers-Analyzer v0.2](https://github.com/evild3ad/Microsoft-Analyzer-Suite/wiki/RiskyUsers%E2%80%90Analyzer)

![RiskyDetections-Analyzer](https://github.com/evild3ad/Microsoft-Analyzer-Suite/blob/bf004f386ed5af210a0b326c24dcf50fccc9adf4/Screenshots/01.png)  
**Fig 1:** RiskyDetections-Analyzer

![RiskyDetections-1](https://github.com/evild3ad/Microsoft-Analyzer-Suite/blob/bf004f386ed5af210a0b326c24dcf50fccc9adf4/Screenshots/02.png)  
**Fig 2:** Risky Detections (1)

![RiskyDetections-2](https://github.com/evild3ad/Microsoft-Analyzer-Suite/blob/bf004f386ed5af210a0b326c24dcf50fccc9adf4/Screenshots/03.png)  
**Fig 3:** Risky Detections (2)

![RiskyDetections-LineChart](https://github.com/evild3ad/Microsoft-Analyzer-Suite/blob/bf004f386ed5af210a0b326c24dcf50fccc9adf4/Screenshots/04.png)  
**Fig 4:** Risky Detections (Line Chart)

![RiskyDetections-mitreTechniques](https://github.com/evild3ad/Microsoft-Analyzer-Suite/blob/bf004f386ed5af210a0b326c24dcf50fccc9adf4/Screenshots/05.png)  
**Fig 5:** MITRE ATT&CK Techniques (Stats)

![RiskyDetections-RiskEventType](https://github.com/evild3ad/Microsoft-Analyzer-Suite/blob/bf004f386ed5af210a0b326c24dcf50fccc9adf4/Screenshots/06.png)  
**Fig 6:** RiskEventType (Stats)

![RiskyDetections-RiskLevel](https://github.com/evild3ad/Microsoft-Analyzer-Suite/blob/bf004f386ed5af210a0b326c24dcf50fccc9adf4/Screenshots/07.png)  
**Fig 7:** RiskLevel (Stats)

![RiskyDetections-Source](https://github.com/evild3ad/Microsoft-Analyzer-Suite/blob/bf004f386ed5af210a0b326c24dcf50fccc9adf4/Screenshots/08.png)  
**Fig 8:** Source (Stats)

![RiskyUsers-Analyzer](https://github.com/evild3ad/Microsoft-Analyzer-Suite/blob/bf004f386ed5af210a0b326c24dcf50fccc9adf4/Screenshots/09.png)  
**Fig 9:** RiskyUsers-Analyzer

![RiskyUsers](https://github.com/evild3ad/Microsoft-Analyzer-Suite/blob/bf004f386ed5af210a0b326c24dcf50fccc9adf4/Screenshots/10.png)  
**Fig 10:** Risky Users

## Links  
[Microsoft-Extractor-Suite by Invictus-IR](https://github.com/invictus-ir/Microsoft-Extractor-Suite)  
[Microsoft-Extractor-Suite Documentation](https://microsoft-365-extractor-suite.readthedocs.io/en/latest/)  
[Microsoft 365 Artifact Reference Guide by the Microsoft Incident Response Team](https://go.microsoft.com/fwlink/?linkid=2257423)  
[Awesome BEC - Repository of attack and defensive information for Business Email Compromise investigations](https://go.microsoft.com/fwlink/?linkid=2257423)  
[M365_Oauth_Apps - Repository of suspicious Enterprise Applications (BEC)](https://github.com/randomaccess3/detections/blob/main/M365_Oauth_Apps/MaliciousOauthAppDetections.json)  