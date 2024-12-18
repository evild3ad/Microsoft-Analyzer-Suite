<div align="center">
  <p>
    <a href="https://github.com/PowerShell/PowerShell">
      <img src="https://img.shields.io/badge/Language-Powershell-blue" style="text-align:center;display:block;" alt="PowerShell">
    </a>  
    <a href="https://github.com/evild3ad/Microsoft-Analyzer-Suite/wiki">
      <img src="https://img.shields.io/badge/Wiki-Documentation-blue" style="text-align:center;display:block;" alt="Wiki">
    </a>  
    <a href="https://github.com/evild3ad/Microsoft-Analyzer-Suite/releases/latest">
      <img src="https://img.shields.io/github/v/release/evild3ad/Microsoft-Analyzer-Suite?label=Release" style="text-align:center;display:block;" alt="Latest Release">
    </a>  
    <img src="https://img.shields.io/badge/Maintenance%20Level-Actively%20Developed-brightgreen" style="text-align:center;display:block;" alt="Maintenance Level">
    <img src="https://img.shields.io/badge/Digital%20Signature-Valid-brightgreen" style="text-align:center;display:block;" alt="Digital Signature">
    <a href="https://twitter.com/Evild3ad79">
      <img src="https://img.shields.io/twitter/follow/Evild3ad79?style=social" style="text-align:center;display:block;" alt="Lethal Forensics on X">
    </a>  
    <a href="https://twitter.com/InvictusIR">
      <img src="https://img.shields.io/twitter/follow/InvictusIR?style=social" style="text-align:center;display:block;" alt="InvictusIR on X">
    </a>  
  </p>
</div>

# Microsoft-Analyzer-Suite (Community Edition)
A collection of PowerShell scripts for analyzing data from Microsoft 365 and Microsoft Entra ID.

## TL;DR  
Automated Processing of Microsoft 365 Logs and Microsoft Entra ID Logs extracted by [Microsoft-Extractor-Suite](https://github.com/invictus-ir/Microsoft-Extractor-Suite).

## The following Microsoft data sources are supported yet:

> Output Files of Microsoft-Extractor-Suite v2.1.1 by Invictus-IR
  * [Get-ADAuditLogsGraph](https://microsoft-365-extractor-suite.readthedocs.io/en/latest/functionality/AzureAuditLogsGraph.html) &#8594; [ADAuditLogsGraph-Analyzer](https://github.com/evild3ad/Microsoft-Analyzer-Suite/wiki/ADAuditLogsGraph%E2%80%90Analyzer)    
  * [Get-ADSignInLogsGraph](https://microsoft-365-extractor-suite.readthedocs.io/en/latest/functionality/AzureSignInLogsGraph.html) &#8594; [ADSignInLogsGraph-Analyzer](https://github.com/evild3ad/Microsoft-Analyzer-Suite/wiki/ADSignInLogsGraph%E2%80%90Analyzer)  
  * [Get-MessageTraceLog](https://microsoft-365-extractor-suite.readthedocs.io/en/latest/functionality/MessageTraceLog.html) &#8594; [MTL-Analyzer](https://github.com/evild3ad/Microsoft-Analyzer-Suite/wiki/MTL%E2%80%90Analyzer)  
  * [Get-MFA](https://microsoft-365-extractor-suite.readthedocs.io/en/latest/functionality/GetUserInfo.html#retrieves-mfa-status) &#8594; [MFA-Analyzer](https://github.com/evild3ad/Microsoft-Analyzer-Suite/wiki/MFA%E2%80%90Analyzer)
  * [Get-OAuthPermissions](https://microsoft-365-extractor-suite.readthedocs.io/en/latest/functionality/OAuthPermissions.html) &#8594; [OAuthPermissions-Analyzer](https://github.com/evild3ad/Microsoft-Analyzer-Suite/wiki/OAuthPermissions%E2%80%90Analyzer)  
  * [Get-RiskyDetections](https://microsoft-365-extractor-suite.readthedocs.io/en/latest/functionality/GetUserInfo.html#retrieves-the-risky-detections) &#8594; [RiskyDetections-Analyzer](https://github.com/evild3ad/Microsoft-Analyzer-Suite/wiki/RiskyDetections%E2%80%90Analyzer)
  * [Get-RiskyUsers](https://microsoft-365-extractor-suite.readthedocs.io/en/latest/functionality/GetUserInfo.html#retrieves-the-risky-users) &#8594; [RiskyUsers-Analyzer](https://github.com/evild3ad/Microsoft-Analyzer-Suite/wiki/RiskyUsers%E2%80%90Analyzer)  
  * [Get-UALAll](https://microsoft-365-extractor-suite.readthedocs.io/en/latest/functionality/UnifiedAuditLog.html) &#8594; [UAL-Analyzer](https://github.com/evild3ad/Microsoft-Analyzer-Suite/wiki/UAL%E2%80%90Analyzer)  
  * [Get-Users](https://microsoft-365-extractor-suite.readthedocs.io/en/latest/functionality/GetUserInfo.html) &#8594; [Users-Analyzer](https://github.com/evild3ad/Microsoft-Analyzer-Suite/wiki/Users%E2%80%90Analyzer)  
  * [Get-TransportRules](https://microsoft-365-extractor-suite.readthedocs.io/en/latest/functionality/TransportRules.html) &#8594; [TransportRules-Analyzer](https://github.com/evild3ad/Microsoft-Analyzer-Suite/wiki/TransportRules%E2%80%90Analyzer)  
  
<br>

> [!TIP]
> Check out the [Wiki](https://github.com/evild3ad/Microsoft-Analyzer-Suite/wiki) for additional documentation!  
  
<br>

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

![UAL-Analyzer](https://github.com/evild3ad/Microsoft-Analyzer-Suite/blob/8092610fb8576040fee6834c52d57b858c666248/Screenshots/11.png)  
**Fig 11:** You can specify a file path or launch the File Browser Dialog to select your log file  

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.  
Note: If your change is larger, or adds a feature, please contact me beforehand so that we can discuss the change.  

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.  

## Links  
[Microsoft-Extractor-Suite by Invictus-IR](https://github.com/invictus-ir/Microsoft-Extractor-Suite)  
[Microsoft-Extractor-Suite Documentation](https://microsoft-365-extractor-suite.readthedocs.io/en/latest/)  
[Microsoft 365 Artifact Reference Guide by the Microsoft Incident Response Team](https://go.microsoft.com/fwlink/?linkid=2257423)  
[Awesome BEC - Repository of attack and defensive information for Business Email Compromise investigations](https://github.com/randomaccess3/Awesome-BEC)  
[M365_Oauth_Apps - Repository of suspicious Enterprise Applications (BEC)](https://github.com/randomaccess3/detections/blob/main/M365_Oauth_Apps/MaliciousOauthAppDetections.json)  
[RogueApps by Huntress Labs](https://huntresslabs.github.io/rogueapps/)  