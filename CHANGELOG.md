# Changelog  

All changes to the Microsoft-Analyzer-Suite will be documented in this file.  

## [1.4.0] - 2025-02-24
### Added
- UAL-Analyzer: Detection of suspicious Inbox Rules via RegEx (incl. Conditional Formatting)
- UAL-Analyzer: MoveToFolder-Blacklist.csv
- UAL-Analyzer: UniqueTokenId and IssuedAtTime added to Hunt View &#8594; correlate with SignInLogs
- UAL-Analyzer: RecordType / Id (Stats)
- UAL-Analyzer: Line Charts - SharePoint (Workload), OneDrive (Workload), and FileDownloaded (SharePoint and OneDrive)
- OAuthPermissions-Analyzer: Microsoft Graph Edition
- OAuthPermissions-Analyzer: Detection of suspicious OAuth Apps (Anomalous ReplyUrls, Common Naming Patterns)

### Fixed
- Minor fixes and improvements

## [1.3.0] - 2025-01-27
### Added
- UAL-Analyzer: UserAgent-Blacklist.csv
- UAL-Analyzer: MailItemsAccessed &#8594; AppId-AppDisplayName (Stats)
- UAL-Analyzer: ClientInfoString and Mailbox Synchronization detection of eM Client (Traitorware)
- EntraAuditLogs-Analyzer: UserAgent-Blacklist.csv
- EntraAuditLogs-Analyzer: Activity (Line Chart)
- EntraSignInLogs-Analyzer: UserAgent-Blacklist.csv
- EntraSignInLogs-Analyzer: SignInEventTypes (Stats)

### Fixed
- ReadTheDocs links of the Microsoft-Extractor-Suite documentation updated
- Multiple minor fixes and improvements

## [1.2.0] - 2025-01-20
### Added
- ADAuditLogsGraph-Analyzer &#8594; EntraAuditLogs-Analyzer
- ADSignInLogsGraph-Analyzer &#8594; EntraSignInLogs-Analyzer
- EntraSignInLogs-Analyzer: Intune Bypass / Device Compliance Bypass
- MailboxAuditStatus-Analyzer
- MailboxPermissions-Analyzer
- Devices-Analyzer
- Helper-Script: Updater v0.3
- SECURITY.md

## [1.1.0] - 2024-12-18
### Added
- Performance Improvement: Inefficient addition operator for arrays &#8594; Generic lists
- ASN-Blacklist updated
- Helper-Script: Get-AssignedRoles.ps1

## [1.0.1] - 2024-11-21
### Fixed
- MFA-Analyzer: Input Filename Change (User Registration Details). Reported by @DoubtfulTurnip

## [1.0.0] - 2024-11-20
### Added
- UAL-Analyzer: UserLoginFailed.xlsx
- UAL-Analyzer: Device Code Authentication failed (CmsiInterrupt)
- IPinfo.io Subscription Check added to all PowerShell scripts
- All PowerShell scripts are now digitally signed with a valid code signing certificate

## Changed
- CHANGELOG.md
