@echo off
cd /d "%~dp0"

echo :::::::::::::::::::::::::::::::::::::::
echo ::  Windows Optimizer Script         ::
echo ::                                   ::
echo ::  Version 1.0.0                    ::
echo ::                                   ::
echo ::  Jun 12, 2025 by  S.H.E.I.K.H     ::
echo :::::::::::::::::::::::::::::::::::::::
echo .
echo For Post-install use only!
echo .
pause


echo .
echo ::::::::::::::::::::::::::::::::::::::::
echo ::::: Disabling Microsoft Defender :::::
echo ::::::::::::::::::::::::::::::::::::::::
echo.

echo Disable Tamper Protection
REG Add "HKLM\Software\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d "0" /f

echo Disable System Guard Runtime Monitor Broker (when disabled, it might cause BSOD Critical Process Died)
REG Add "HKLM\System\CurrentControlSet\Services\SgrmBroker" /v "Start" /t REG_DWORD /d "4" /f

echo Disable Windows Defender Security Center
REG Add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f

echo Disable Antivirus Notifications
REG Add "HKLM\Software\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d "1" /f
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableEnhancedNotifications " /t REG_DWORD /d "1" /f

echo Disable Security and Maitenance Notification
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d "0" /f

echo Disable Real-time protection
reg delete "HKLM\Software\Policies\Microsoft\Windows Defender" /f
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "AllowFastServiceStartup" /t REG_DWORD /d "0" /f
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableSpecialRunningModes" /t REG_DWORD /d "1" /f
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "0" /f
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /f
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SpynetReporting" /t REG_DWORD /d "0" /f
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f

echo Disable Logging
REG Add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f
REG Add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f

echo Disable Tasks
schtasks /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable

echo Disable systray icon
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f

echo echoove context menu
reg delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /f
reg delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /f
reg delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /f

echo Disable services
REG Add "HKLM\System\CurrentControlSet\Services\WdBoot" /v "Start" /t REG_DWORD /d "4" /f
REG Add "HKLM\System\CurrentControlSet\Services\MDCoreSvc" /v "Start" /t REG_DWORD /d "4" /f
REG Add "HKLM\System\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d "4" /f
REG Add "HKLM\System\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f
REG Add "HKLM\System\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f
REG Add "HKLM\System\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f

echo OWeb Threat Defense Service (Phishing protection)
sc config webthreatdefsvc start= disabled

echo Web Threat Defense User Service (Phishing protection)
sc config webthreatdefusersvc start= disabled

echo Disable Windows SmartScreen
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f

echo Disable SmartScreen Filter in Microsoft Edge
REG Add "HKCU\Software\Microsoft\Edge\SmartScreenEnabled" /ve /t REG_DWORD /d "0" /f

echo Disable SmartScreen PUA in Microsoft Edge 
REG Add "HKCU\Software\Microsoft\Edge\SmartScreenPuaEnabled" /ve /t REG_DWORD /d "0" /f

echo Disable Windows SmartScreen for Windows Store Apps
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t "REG_DWORD" /d "0" /f

echo echoove Smartscreen (to restore run "sfc /scannow")
takeown /s %computername% /u %username% /f "%WinDir%\System32\smartscreen.exe"
icacls "%WinDir%\System32\smartscreen.exe" /grant:r %username%:F
taskkill /im smartscreen.exe /f
del "%WinDir%\System32\smartscreen.exe" /s /f /q

echo Disable Smart App Control blocking legitimate apps
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "VerifiedAndReputablePolicyState" /t REG_DWORD /d "0" /f

echo Other Registries
REG Add "HKLM\Software\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d "0" /f
REG Add "HKLM\System\CurrentControlSet\Control\CI\Policy" /v "PUAProtection" /t REG_DWORD /d "0" /f
REG Add "HKLM\System\CurrentControlSet\Control\CI\Policy" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
REG Add "HKLM\System\CurrentControlSet\Control\CI\Policy" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V SettingsPageVisibility /T REG_SZ /D hide:home /F


echo .
echo ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
echo ::::: Disabling Auto-install subscribed/suggested apps :::::
echo ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
echo .

REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d "0" /f
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatuechoanagementEnabled" /t REG_DWORD /d "0" /f
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d "0" /f
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d "0" /f
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d "0" /f
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d "0" /f
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d "0" /f
REG Add "HKLM\Software\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d "0" /f
REG Add "HKLM\Software\Policies\Microsoft\PushToInstall" /v "DisablePushToInstall" /t REG_DWORD /d "1" /f
REG Add "HKLM\Software\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /f


echo .
echo :::::::::::::::::::::::::::::::::
echo ::::: Disabling Hibernation :::::
echo :::::::::::::::::::::::::::::::::
echo .

powercfg.exe /hibernate off
powercfg -h off


echo .
echo ::::::::::::::::::::::::::::::::::::::::::::::::
echo ::::: Disabling Windows Recovery Partition :::::
echo ::::::::::::::::::::::::::::::::::::::::::::::::
echo .

reagentc /info
reagentc /disable


echo .
echo ::::::::::::::::::::::::::::::::::::::
echo ::::: Disabling Reserved Storage :::::
echo ::::::::::::::::::::::::::::::::::::::
echo .

fsutil storagereserve query C:
Dism /Online /Set-ReservedStorageState /State:Disabled /Quiet /NoRestart
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /v "MiscPolicyInfo" /t REG_DWORD /d "2" /f
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /v "PassedPolicy" /t REG_DWORD /d "0" /f
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /v "ShippedWithReserves" /t REG_DWORD /d "0" /f


echo .
echo :::::::::::::::::::::::::::::::::::::::::::::
echo ::::: Disabling Windows Error Reporting :::::
echo :::::::::::::::::::::::::::::::::::::::::::::
echo .

echo Disable Microsoft Support Diagnostic Tool MSDT
REG Add "HKLM\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v "DisableQueryechooteServer" /t REG_DWORD /d "0" /f
REG Add "HKLM\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v "EnableQueryechooteServer" /t REG_DWORD /d "0" /f

echo Disable System Debugger (Dr. Watson)
REG Add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AeDebug" /v "Auto" /t REG_SZ /d "0" /f

echo Disable Windows Error Reporting (WER)
REG Add "HKLM\Software\Microsoft\PCHealth\ErrorReporting" /v "DoReport" /t REG_DWORD /d "0" /f
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
REG Add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f

echo DefaultConsent / 1 - Always ask (default) / 2 - Parameters only / 3 - Parameters and safe data / 4 - All data
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d "0" /f
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d "1" /f
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d "0" /f
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d "1" /f

echo 1 - Disable WER sending second-level data
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f

echo 1 - Disable WER crash dialogs, popups
REG Add "HKLM\Software\Microsoft\PCHealth\ErrorReporting" /v "ShowUI" /t REG_DWORD /d "0" /f
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d "1" /f
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d "1" /f

echo 1 - Disable WER logging
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f

schtasks /Change /TN "Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable

echo Windows Error Reporting Service
sc config WerSvc start= disabled


echo .
echo ::::::::::::::::::::::::::::::::::::
echo ::::: Windows Explorer Options :::::
echo ::::::::::::::::::::::::::::::::::::
echo .

echo Open File Explorer to This PC
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d "1" /f

echo Disable recently used folders
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d "0" /f

echo Disable frequently used folders
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d "0" /f

echo Disable Show files from Office.com
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowCloudFilesInQuickAccess" /t REG_DWORD /d "0" /f

echo Disable Network Icon from Navigation Panel / Right in Nav Panel
REG Add "HKCR\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\ShellFolder" /v "Attributes" /t REG_DWORD /d "2962489444" /f

echo echoove Gallery from Navigation Pane in File Explorer
REG Add "HKCU\Software\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f

echo echoove 3D Folders from This PC
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f

echo echoove Home (Quick access) from This PC
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "HubMode" /t REG_DWORD /d "1" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /f


echo Show hidden files, folders and drives
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "1" /f

echo Show extensions for known file types
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f

echo Always show more details in copy dialog
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v "EnthusiastMode" /t REG_DWORD /d "1" /f


echo .
echo ::::::::::::::::::::::::::::::
echo ::::: Setting Registries :::::
echo ::::::::::::::::::::::::::::::
echo .

REG Add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /V CrashDumpEnabled /T REG_DWORD /D 0 /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /V NtfsDisableLastAccessUpdate /T REG_DWORD /D 80000001 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V DisableechoovableDriveIndexing /T REG_DWORD /D 1 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V PreventUsingAdvancedIndexingOptions /T REG_DWORD /D 1 /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /V RPSessionInterval /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /V Disabled /T REG_DWORD /D 1 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /V Disabled /T REG_DWORD /D 1 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /V EnableActivityFeed /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /V PublishUserActivities /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /V UploadUserActivities /T REG_DWORD /D 0 /F
REG Add "HKLM\System\CurrentControlSet\Control\Session Manager\Power" /V HibernateEnabled /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /V ShowHibernateOption /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /V Value /T REG_SZ /D Deny /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /V SensorPermissionState /T REG_DWORD /D 0 /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /V Status /T REG_DWORD /D 0 /F
REG Add "HKLM\SYSTEM\Maps" /V AutoUpdateEnabled /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" /V CreateDesktopShortcutDefault /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V PersonalizationReportingEnabled /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V ShowRecommendationsEnabled /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V HideFirstRunExperience /T REG_DWORD /D 1 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V UserFeedbackAllowed /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V ConfigureDoNotTrack /T REG_DWORD /D 1 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V AlternateErrorPagesEnabled /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V EdgeCollectionsEnabled /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V EdgeShoppingAssistantEnabled /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V MicrosoftEdgeInsiderPromotionEnabled /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V PersonalizationReportingEnabled /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V ShowMicrosoftRewards /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V WebWidgetAllowed /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V DiagnosticData /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V EdgeAssetDeliveryServiceEnabled /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V EdgeCollectionsEnabled /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V CryptoWalletEnabled /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V WalletDonationEnabled /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V DisableWindowsConsumerFeatures /T REG_DWORD /D 1 /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /V AllowTelemetry /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /V AllowTelemetry /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V ContentDeliveryAllowed /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V OemPreInstalledAppsEnabled /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V PreInstalledAppsEnabled /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V PreInstalledAppsEverEnabled /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V SilentInstalledAppsEnabled /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V SubscribedContent-338387Enabled /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V SubscribedContent-338388Enabled /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V SubscribedContent-338389Enabled /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V SubscribedContent-353698Enabled /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V SystemPaneSuggestionsEnabled /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Microsoft\Siuf\Rules" /V NumberOfSIUFInPeriod /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V NumberOfSIUFInPeriod /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /V DoNotShowFeedbackNotifications /T REG_DWORD /D 1 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V DisableTailoredExperiencesWithDiagnosticData /T REG_DWORD /D 1 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /V DisabledByGroupPolicy /T REG_DWORD /D 1 /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /V Disabled /T REG_DWORD /D 1 /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /V DODownloadMode /T REG_DWORD /D 1 /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Control\echoote Assistance" /V fAllowToGetHelp /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /V EnthusiastMode /T REG_DWORD /D 1 /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /V PeopleBand /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V LaunchTo /T REG_DWORD /D 1 /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /V LongPathsEnabled /T REG_DWORD /D 1 /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /V SearchOrderConfig /T REG_DWORD /D 1 /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /V SystemResponsiveness /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /V NetworkThrottlingIndex /T REG_DWORD /D 4294967295 /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /V ClearPageFileAtShutdown /T REG_DWORD /D 0 /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\Ndu" /V Start /T REG_DWORD /D 2 /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /V IRPStackSize /T REG_DWORD /D 30 /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V HideSCAMeetNow /T REG_DWORD /D 1 /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /V ScoobeSystemSettingEnabled /T REG_DWORD /D 0 /F
REG Add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /V Value /T REG_DWORD /D 0 /F
REG Add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /V Value /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" /V TurnOffWindowsCopilot /T REG_DWORD /D 1 /F
REG Add "HKLM\Software\Policies\Microsoft\Windows\WindowsCopilot" /V TurnOffWindowsCopilot /T REG_DWORD /D 1 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /V DisableAIDataAnalysis /T REG_DWORD /D 1 /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /V DisableWpbtExecution /T REG_DWORD /D 1 /F
REG Add "HKLM\System\GameConfigStore" /V GameDVR_FSEBehavior /T REG_DWORD /D 2 /F
REG Add "HKLM\System\GameConfigStore" /V GameDVR_Enabled /T REG_DWORD /D 0 /F
REG Add "HKLM\System\GameConfigStore" /V GameDVR_HonorUserFSEBehaviorMode /T REG_DWORD /D 1 /F
REG Add "HKLM\System\GameConfigStore" /V GameDVR_EFSEFeatureFlags /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /V AllowGameDVR /T REG_DWORD /D 0 /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /V GlobalUserDisabled /T REG_DWORD /D 1 /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Search" /V BingSearchEnabled /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Education" /V IsEducationEnvironment /T REG_DWORD /D 0 /F


echo .
echo :::::::::::::::::::::::::::::
echo ::::: Setting Services :::::
echo :::::::::::::::::::::::::::::
echo .

sc stop "WinDefend"
sc config "WinDefend" start=disabled
sc stop "MDCoreSvc"
sc config "MDCoreSvc" start=disabled
sc stop "wsearch"
sc config "wsearch" start=disabled
sc stop "SysMain"
sc config "SysMain" start=disabled
sc stop "AJRouter"
sc config "AJRouter" start=disabled
sc stop "AppVClient"
sc config "AppVClient" start=disabled
sc stop "AssignedAccessManagerSvc"
sc config "AssignedAccessManagerSvc" start=disabled
sc stop "DiagTrack"
sc config "DiagTrack" start=disabled
sc stop "DialogBlockingService"
sc config "DialogBlockingService" start=disabled
sc stop "NetTcpPortSharing"
sc config "NetTcpPortSharing" start=disabled
sc stop "echooteAccess"
sc config "echooteAccess" start=disabled
sc stop "echooteRegistry"
sc config "echooteRegistry" start=disabled
sc stop "UevAgentService"
sc config "UevAgentService" start=disabled
sc stop "shpamsvc"
sc config "shpamsvc" start=disabled
sc stop "ssh-agent"
sc config "ssh-agent" start=disabled
sc stop "tzautoupdate"
sc config "tzautoupdate" start=disabled
sc stop "uhssvc"
sc config "uhssvc" start=disabled
sc stop "CertPropSvc"
sc config "CertPropSvc" start=disabled
sc stop "CDPSvc"
sc config "CDPSvc" start=disabled
sc stop "diagsvc"
sc config "diagsvc" start=disabled
sc stop "Fax"
sc config "Fax" start=disabled
sc stop "fdPHost"
sc config "fdPHost" start=disabled
sc stop "FDResPub"
sc config "FDResPub" start=disabled
sc stop "GraphicsPerfSvc"
sc config "GraphicsPerfSvc" start=disabled
sc stop "wlidsvc"
sc config "wlidsvc" start=disabled
sc stop "MsKeyboardFilter"
sc config "MsKeyboardFilter" start=disabled
sc stop "CscService"
sc config "CscService" start=disabled
sc stop "XblAuthManager"
sc config "XblAuthManager" start=disabled
sc stop "XblGameSave"
sc config "XblGameSave" start=disabled
sc stop "XboxGipSvc"
sc config "XboxGipSvc" start=disabled
sc stop "XboxNetApiSvc"
sc config "XboxNetApiSvc" start=disabled
sc stop "RasMan"
sc config "RasMan" start=disabled
sc stop "RetailDemo"
sc config "RetailDemo" start=disabled
sc stop "SCPolicySvc"
sc config "SCPolicySvc" start=disabled
sc stop "SSDPSRV"
sc config "SSDPSRV" start=disabled
sc stop "lmhosts"
sc config "lmhosts" start=disabled
sc stop "WerSvc"
sc config "WerSvc" start=disabled
sc stop "WMPNetworkSvc"
sc config "WMPNetworkSvc" start=disabled
sc stop "WinRM"
sc config "WinRM" start=disabled


echo .
echo :::::::::::::::::::::::::::::::::::
echo ::::: Setting Scheduled Tasks :::::
echo :::::::::::::::::::::::::::::::::::
echo .

schtasks /Change /Disable /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
schtasks /Change /Disable /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater"
schtasks /Change /Disable /TN "Microsoft\Windows\Autochk\Proxy"
schtasks /Change /Disable /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
schtasks /Change /Disable /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
schtasks /Change /Disable /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
schtasks /Change /Disable /TN "Microsoft\Windows\Feedback\Siuf\DmClient"
schtasks /Change /Disable /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload"
schtasks /Change /Disable /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting"
schtasks /Change /Disable /TN "Microsoft\Windows\Application Experience\MareBackup"
schtasks /Change /Disable /TN "Microsoft\Windows\Application Experience\StartupAppTask"
schtasks /Change /Disable /TN "Microsoft\Windows\Application Experience\PcaPatchDbTask"
schtasks /Change /Disable /TN "Microsoft\Windows\Maps\MapsUpdateTask"
schtasks /Change /Disable /TN "\Microsoft\XblGameSave\XblGameSaveTask"
schtasks /Change /Disable /TN "\Microsoft\Windows\BitLocker\BitLocker Encrypt All Drives"
schtasks /Change /Disable /TN "\Microsoft\Windows\BitLocker\BitLocker MDM policy Refresh"
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319" /Disable
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64" /Disable
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical" /Disable
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\PcaPatchDbTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\SdbinstMergeDbTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "Microsoft\Windows\Defrag\ScheduledDefrag" /Disable
schtasks /Change /TN "Microsoft\Windows\Device Information\Device" /Disable
schtasks /Change /TN "Microsoft\Windows\Device Information\Device User" /Disable
schtasks /Change /TN "Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" /Disable
schtasks /Change /TN "Microsoft\Windows\Diagnosis\Scheduled" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskCleanup\SilentCleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\StorageSense" /Disable
schtasks /Change /TN "Microsoft\Windows\DUSM\dusmtask" /Disable
schtasks /Change /TN "Microsoft\Windows\EnterpriseMgmt\MDMMaintenenceTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /Disable
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\ReconcileFeatures" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataFlushing" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataReporting" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\OneSettings\RefreshCache" /Disable
schtasks /Change /TN "Microsoft\Windows\Input\LocalUserSyncDataAvailable" /Disable
schtasks /Change /TN "Microsoft\Windows\Input\MouseSyncDataAvailable" /Disable
schtasks /Change /TN "Microsoft\Windows\Input\PenSyncDataAvailable" /Disable
schtasks /Change /TN "Microsoft\Windows\Input\TouchpadSyncDataAvailable" /Disable
schtasks /Change /TN "Microsoft\Windows\International\Synchronize Language Settings" /Disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Installation" /Disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources" /Disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Uninstallation" /Disable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /Disable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /Disable
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Cellular" /Disable
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Logon" /Disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsToastTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsUpdateTask" /Disable
schtasks /Change /TN "Microsoft\Windows\MUI\LPechoove" /Disable
schtasks /Change /TN "Microsoft\Windows\Multimedia\SystemSoundsService" /Disable
schtasks /Change /TN "Microsoft\Windows\NlaSvc\WiFiTask" /Disable
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Disable
schtasks /Change /TN "Microsoft\Windows\Printing\EduPrintProv" /Disable
schtasks /Change /TN "Microsoft\Windows\Printing\PrinterCleanupTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Printing\PrintJobCleanupTask" /Disable
schtasks /Change /TN "Microsoft\Windows\PushToInstall\Registration" /Disable
schtasks /Change /TN "Microsoft\Windows\Ras\MobilityManager" /Disable
schtasks /Change /TN "Microsoft\Windows\RecoveryEnvironment\VerifyWinRE" /Disable
schtasks /Change /TN "Microsoft\Windows\echooteAssistance\echooteAssistanceTask" /Disable
schtasks /Change /TN "Microsoft\Windows\RetailDemo\CleanupOfflineContent" /Disable
schtasks /Change /TN "Microsoft\Windows\Servicing\StartComponentCleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\SettingSync\NetworkStateChangeTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Setup\SetupCleanupTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Setup\SnapshotCleanupTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefreshTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\ThemesSyncedImageDownload" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\UpdateUserPictureTask" /Disable
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceAgentTask" /Disable
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceManagerTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Speech\SpeechModelDownloadTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Storage Tiers Management\Storage Tiers Management Initialization" /Disable
schtasks /Change /TN "Microsoft\Windows\Sysmain\ResPriStaticDbSync" /Disable
schtasks /Change /TN "Microsoft\Windows\Sysmain\WsSwapAssessmentTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Task Manager\Interactive" /Disable
schtasks /Change /TN "Microsoft\Windows\TextServicesFramework\MsCtfMonitor" /Disable
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable
schtasks /Change /TN "Microsoft\Windows\Time Zone\SynchronizeTimeZone" /Disable
schtasks /Change /TN "Microsoft\Windows\TPM\Tpm-HASCertRetr" /Disable
schtasks /Change /TN "Microsoft\Windows\TPM\Tpm-Maintenance" /Disable
schtasks /Change /TN "Microsoft\Windows\UPnP\UPnPHostConfig" /Disable
schtasks /Change /TN "Microsoft\Windows\UPnP\UPnPHostConfig" /Disable
schtasks /Change /TN "Microsoft\Windows\User Profile Service\HiveUploadTask" /Disable
schtasks /Change /TN "Microsoft\Windows\WCM\WiFiTask" /Disable
schtasks /Change /TN "Microsoft\Windows\WDI\ResolutionHost" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" /Disable
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Scheduled Start" /Disable
schtasks /Change /TN "Microsoft\Windows\WlanSvc\CDSSync" /Disable
schtasks /Change /TN "Microsoft\Windows\WOF\WIM-Hash-Management" /Disable
schtasks /Change /TN "Microsoft\Windows\WOF\WIM-Hash-Validation" /Disable
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Logon Synchronization" /Disable
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Maintenance Work" /Disable
schtasks /Change /TN "Microsoft\Windows\Workplace Join\Automatic-Device-Join" /Disable
schtasks /Change /TN "Microsoft\Windows\WwanSvc\NotificationTask" /Disable
schtasks /Change /TN "Microsoft\Windows\WwanSvc\OobeDiscovery" /Disable


echo .
echo :::::::::::::::::::::::::::
echo ::::: Finishing Setup :::::
echo :::::::::::::::::::::::::::
echo .

fsutil behavior set disablelastaccess 1
fsutil behavior set disabledeletenotify 0
DISM /Online /Disable-Feature /FeatureName:Recall /Quiet /NoRestart


echo .
echo ::::::::::::::::::::::::::::::
echo ::::: Cleaning DISM Temp :::::
echo ::::::::::::::::::::::::::::::
echo .

dism /online /echoove-package /packagename:Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.1742.1.10
dism /online /cleanup-image /analyzecomponentstore
dism /online /cleanup-image /startcomponentcleanup
dism /online /cleanup-image /startcomponentcleanup /resetbase


echo .
echo :::::::::::::::::::::::::
echo ::::: Checking Disk :::::
echo :::::::::::::::::::::::::
echo .

chkdsk


echo .
echo :::::::::::::::::::::::::::::
echo ::::: Repairing Windows :::::
echo :::::::::::::::::::::::::::::
echo .

dism /online /cleanup-image /checkhealth >nul 2>&1
dism /online /cleanup-image /scanhealth
dism /online /cleanup-image /restorehealth
sfc /verifyonly
sfc /scannow


echo .
echo ::::::::::::::::::::::::::::::
echo ::::: Cleaning Edge Temp :::::
echo ::::::::::::::::::::::::::::::
echo .

del /s /q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History*" >nul 2>&1
del /s /q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Media History*" >nul 2>&1
del /s /q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Visited Links*" >nul 2>&1
del /s /q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Top Sites*" >nul 2>&1
del /s /q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Network Action Predictor*" >nul 2>&1
del /s /q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Shortcuts*" >nul 2>&1
del /s /q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Network\Cookies*" >nul 2>&1
del /s /q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Web Data*" >nul 2>&1
pushd "%LocalAppData%\Microsoft\Edge\User Data\Default\Session Storage" && (rd /s /q "%LocalAppData%\Microsoft\Edge\User Data\Default\Session Storage" 2>nul & popd)
pushd "%LocalAppData%\Microsoft\Edge\User Data\Default\Sync Data" && (rd /s /q "%LocalAppData%\Microsoft\Edge\User Data\Default\Sync Data" 2>nul & popd)
pushd "%LocalAppData%\Microsoft\Edge\User Data\Default\Telemetry" && (rd /s /q "%LocalAppData%\Microsoft\Edge\User Data\Default\Telemetry" 2>nul & popd)
pushd "%LocalAppData%\Microsoft\Edge\User Data\CrashReports" && (rd /s /q "%LocalAppData%\Microsoft\Edge\User Data\CrashReports" 2>nul & popd)
pushd "%LocalAppData%\Microsoft\EdgeUpdate\Log" && (rd /s /q "%LocalAppData%\Microsoft\EdgeUpdate\Log" 2>nul & popd)
pushd "%LocalAppData%\Microsoft\EdgeUpdate\Download" && (rd /s /q "%LocalAppData%\Microsoft\EdgeUpdate\Download" 2>nul & popd)
pushd "%LocalAppData%\Microsoft\EdgeUpdate\Install" && (rd /s /q "%LocalAppData%\Microsoft\EdgeUpdate\Install" 2>nul & popd)
pushd "%LocalAppData%\Microsoft\EdgeUpdate\Offline" && (rd /s /q "%LocalAppData%\Microsoft\EdgeUpdate\Offline" 2>nul & popd)
pushd "%LocalAppData%\Microsoft\Edge\User Data\BrowserMetrics" && (rd /s /q "%LocalAppData%\Microsoft\Edge\User Data\BrowserMetrics" 2>nul & popd)
pushd "%LocalAppData%\Microsoft\Edge\User Data\Crashpad\reports" && (rd /s /q "%LocalAppData%\Microsoft\Edge\User Data\Crashpad\reports" 2>nul & popd)
pushd "%LocalAppData%\Microsoft\Edge\User Data\Stability" && (rd /s /q "%LocalAppData%\Microsoft\Edge\User Data\Stability" 2>nul & popd)
pushd "%LocalAppData%\Microsoft\Edge\User Data\Stability" && (rd /s /q "%LocalAppData%\Microsoft\Edge\User Data\Stability" 2>nul & popd)
pushd "%LocalAppData%\Microsoft\Edge\User Data\Feature Engagement Tracker" && (rd /s /q "%LocalAppData%\Microsoft\Edge\User Data\Feature Engagement Tracker" 2>nul & popd)


echo .
echo ::::::::::::::::::::::::::::::::
echo ::::: Cleaning Office Temp :::::
echo ::::::::::::::::::::::::::::::::
echo .

pushd "%LOCALAPPDATA%\Microsoft\Office\16.0\Wef\" && (rd /s /q "%LOCALAPPDATA%\Microsoft\Office\16.0\Wef\" 2>nul & popd)
pushd "%userprofile%\AppData\Local\Packages\Microsoft.Win32WebViewHost_cw5n1h2txyewy\AC\#!123\INetCache\" && (rd /s /q "%userprofile%\AppData\Local\Packages\Microsoft.Win32WebViewHost_cw5n1h2txyewy\AC\#!123\INetCache\" 2>nul & popd)
pushd "%userprofile%\AppData\Local\Microsoft\Outlook\HubAppFileCache" && (rd /s /q "%userprofile%\AppData\Local\Microsoft\Outlook\HubAppFileCache" 2>nul & popd)


echo .
echo :::::::::::::::::::::::::::::::::
echo ::::: Cleaning Windows Temp :::::
echo :::::::::::::::::::::::::::::::::
echo .

rundll32.exe pnpclean.dll,RunDLL_PnpClean /drivers /maxclean
cleanmgr /sagerun 1
cleanmgr /verylowdisk
C:\Windows\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 1
C:\Windows\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 2
C:\Windows\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 4
C:\Windows\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 8
C:\Windows\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 10
C:\Windows\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 16
C:\Windows\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 20
C:\Windows\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 32
C:\Windows\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 64
C:\Windows\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 40
C:\Windows\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 80
C:\Windows\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 128
C:\Windows\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 255
C:\Windows\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 800
C:\Windows\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 4351
pushd "C:\Windows\Temp" && (rd /s /q "C:\Windows\Temp" 2>nul & popd)
pushd "%LOCALAPPDATA%\Temp" && (rd /s /q "%LOCALAPPDATA%\Temp" 2>nul & popd)
pushd "C:\Windows\Prefetch" && (rd /s /q "C:\Windows\Prefetch" 2>nul & popd)
pushd "C:\$Recycle.Bin" && (rd /s /q "C:\$Recycle.Bin" 2>nul & popd)
pushd "%LocalAppData%\Microsoft\Windows\WER" && (rd /s /q "%LocalAppData%\Microsoft\Windows\WER" 2>nul & popd)
pushd "%LocalAppData%\Microsoft\Windows\INetCache" && (rd /s /q "%LocalAppData%\Microsoft\Windows\INetCache" 2>nul & popd)
pushd "%LocalAppData%\Microsoft\Windows\INetCookies" && (rd /s /q "%LocalAppData%\Microsoft\Windows\INetCookies" 2>nul & popd)
pushd "%LocalAppData%\Microsoft\Windows\IECompatCache" && (rd /s /q "%LocalAppData%\Microsoft\Windows\IECompatCache" 2>nul & popd)
pushd "%LocalAppData%\Microsoft\Windows\IECompatUaCache" && (rd /s /q "%LocalAppData%\Microsoft\Windows\IECompatUaCache" 2>nul & popd)
pushd "%LocalAppData%\Microsoft\Windows\IEDownloadHistory" && (rd /s /q "%LocalAppData%\Microsoft\Windows\IEDownloadHistory" 2>nul & popd)
pushd "%LocalAppData%\Microsoft\Windows\Temporary Internet Files" && (rd /s /q "%LocalAppData%\Microsoft\Windows\Temporary Internet Files" 2>nul & popd)


echo .
echo :::::::::::::::::::::::::::::
echo ::::: Disk Optimization :::::
echo :::::::::::::::::::::::::::::
echo .

defrag /C /O


echo .
echo :::::::::::::::::::
echo ::::: shutdown ::::
echo :::::::::::::::::::
echo .

pushd "C:\Windows\Temp" && (rd /s /q "C:\Windows\Temp" 2>nul & popd)
pushd "%LOCALAPPDATA%\Temp" && (rd /s /q "%LOCALAPPDATA%\Temp" 2>nul & popd)
pushd "C:\Windows\Prefetch" && (rd /s /q "C:\Windows\Prefetch" 2>nul & popd)
pushd "C:\$Recycle.Bin" && (rd /s /q "C:\$Recycle.Bin" 2>nul & popd)
pushd "%LocalAppData%\Microsoft\Windows\WER" && (rd /s /q "%LocalAppData%\Microsoft\Windows\WER" 2>nul & popd)
pushd "%LocalAppData%\Microsoft\Windows\INetCache" && (rd /s /q "%LocalAppData%\Microsoft\Windows\INetCache" 2>nul & popd)
pushd "%LocalAppData%\Microsoft\Windows\INetCookies" && (rd /s /q "%LocalAppData%\Microsoft\Windows\INetCookies" 2>nul & popd)
pushd "%LocalAppData%\Microsoft\Windows\IECompatCache" && (rd /s /q "%LocalAppData%\Microsoft\Windows\IECompatCache" 2>nul & popd)
pushd "%LocalAppData%\Microsoft\Windows\IECompatUaCache" && (rd /s /q "%LocalAppData%\Microsoft\Windows\IECompatUaCache" 2>nul & popd)
pushd "%LocalAppData%\Microsoft\Windows\IEDownloadHistory" && (rd /s /q "%LocalAppData%\Microsoft\Windows\IEDownloadHistory" 2>nul & popd)
pushd "%LocalAppData%\Microsoft\Windows\Temporary Internet Files" && (rd /s /q "%LocalAppData%\Microsoft\Windows\Temporary Internet Files" 2>nul & popd)

echo :: Optimization completed successfully. :: Script by S.H.E.I.K.H


echo .
echo :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
echo :::: Warning! Press any key to shutdown or simply close this batch file. ::::
echo :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

pause
shutdown /s /t 0
