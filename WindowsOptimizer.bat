@ECHO OFF
SETLOCAL EnableDelayedExpansion
SET version=4.0.0
title Install Optimizer Script - by S.H.E.I.K.H (V. %version%)

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Check to see if this batch file is being run as Administrator. If it is not, then rerun the batch file ::
:: automatically as admin and terminate the initial instance of the batch file.                           ::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

(Fsutil Dirty Query %SystemDrive%>Nul)||(PowerShell start """%~f0""" -verb RunAs & Exit /B) > NUL 2>&1

::::::::::::::::::::::::::::::::::::::::::::::::
:: End Routine to check if being run as Admin ::
::::::::::::::::::::::::::::::::::::::::::::::::

CD /D "%~dp0"
CLS

ECHO :::::::::::::::::::::::::::::::::::::::
ECHO ::     Install Optimizer Script      ::
ECHO ::                                   ::
ECHO ::      Version %version% (Stable)       ::
ECHO ::                                   ::
ECHO ::   Jul 14, 2025 by  S.H.E.I.K.H    ::
ECHO ::                                   ::
ECHO ::       GitHub: Sheikh98-DEV        ::
ECHO :::::::::::::::::::::::::::::::::::::::
ECHO .
ECHO For Post-install use only.
ECHO Recommended to re-launch after Windows updates.
ECHO .
Pause


ECHO .
ECHO :::::::::::::::::::::::::
ECHO ::::: Checking Disk :::::
ECHO :::::::::::::::::::::::::
ECHO .

CHKDSK


ECHO .
ECHO ::::::::::::::::::::::::::::::
ECHO ::::: Cleaning DISM Temp :::::
ECHO ::::::::::::::::::::::::::::::
ECHO .

DISM /Online /Cleanup-Image /AnalyzeComponentStore
DISM /online /Remove-package /PackageName:Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.1742.1.10
DISM /Online /Cleanup-Image /StartComponentCleanup
DISM /Online /Cleanup-Image /StartComponentCleanup /ResetBase


ECHO .
ECHO :::::::::::::::::::::::::::::
ECHO ::::: Repairing Windows :::::
ECHO :::::::::::::::::::::::::::::
ECHO .

DISM /Online /Cleanup-Image /CheckHealth >nul 2>&1
DISM /Online /Cleanup-Image /ScanHealth
DISM /Online /Cleanup-Image /RestoreHealth
SFC /ScanNow
DISM /Online /Cleanup-Image /AnalyzeComponentStore
DISM /Online /Cleanup-Image /StartComponentCleanup
DISM /Online /Cleanup-Image /StartComponentCleanup /ResetBase


ECHO .
ECHO ::::::::::::::::::::::::::::::
ECHO ::::: Setting Registries :::::
ECHO ::::::::::::::::::::::::::::::
ECHO .

REG Add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /V "CrashDumpEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /V "NtfsDisableLastAccessUpdate" /T "REG_DWORD" /D "80000001" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "DisableechoovableDriveIndexing" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "PreventUsingAdvancedIndexingOptions" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /V "RPSessionInterval" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /V "Disabled" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /V "EnableActivityFeed" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /V "PublishUserActivities" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /V "UploadUserActivities" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\System\CurrentControlSet\Control\Session Manager\Power" /V "HibernateEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /V "ShowHibernateOption" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /V "Value" /T "REG_SZ" /D Deny /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /V "SensorPermissionState" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /V "Status" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SYSTEM\Maps" /V "AutoUpdateEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" /V "CreateDesktopShortcutDefault" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "PersonalizationReportingEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "ShowRecommendationsEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "HideFirstRunExperience" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "UserFeedbackAllowed" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "ConfigureDoNotTrack" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "AlternateErrorPagesEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "EdgeCollectionsEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "EdgeShoppingAssistantEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "MicrosoftEdgeInsiderPromotionEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "ShowMicrosoftRewards" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "WebWidgetAllowed" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "DiagnosticData" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "EdgeAssetDeliveryServiceEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "CryptoWalletEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "WalletDonationEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /V "AllowTelemetry" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /V "AllowTelemetry" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "ContentDeliveryAllowed" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEverEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338387Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338388Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338389Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353698Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SystemPaneSuggestionsEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\Siuf\Rules" /V "NumberOfSIUFInPeriod" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "NumberOfSIUFInPeriod" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /V "DoNotShowFeedbackNotifications" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V "DisableTailoredExperiencesWithDiagnosticData" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /V "DisabledByGroupPolicy" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /V "Disabled" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /V "DODownloadMode" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Control\echoote Assistance" /V "fAllowToGetHelp" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /V "EnthusiastMode" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /V "PeopleBand" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "LaunchTo" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /V "LongPathsEnabled" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /V "SearchOrderConfig" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /V "SystemResponsiveness" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /V "NetworkThrottlingIndex" /T "REG_DWORD" /D "4294967295" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /V "ClearPageFileAtShutdown" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\Ndu" /V "Start" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /V "IRPStackSize" /T "REG_DWORD" /D "30" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V "HideSCAMeetNow" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /V "ScoobeSystemSettingEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /V "Value" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /V "Value" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" /V "TurnOffWindowsCopilot" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\Software\Policies\Microsoft\Windows\WindowsCopilot" /V "TurnOffWindowsCopilot" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /V "DisableAIDataAnalysis" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /V "DisableWpbtExecution" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\System\GameConfigStore" /V "GameDVR_FSEBehavior" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\System\GameConfigStore" /V "GameDVR_Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\System\GameConfigStore" /V "GameDVR_HonorUserFSEBehaviorMode" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\System\GameConfigStore" /V "GameDVR_EFSEFeatureFlags" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /V "GlobalUserDisabled" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Education" /V "IsEducationEnvironment" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SYSTEM\CurrentControlSet\Control\CrashControl" /V "CrashDumpEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SYSTEM\CurrentControlSet\Control\FileSystem" /V "NtfsDisableLastAccessUpdate" /T "REG_DWORD" /D "80000001" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "DisableechoovableDriveIndexing" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "PreventUsingAdvancedIndexingOptions" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /V "RPSessionInterval" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /V "Disabled" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\System" /V "EnableActivityFeed" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\System" /V "PublishUserActivities" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\System" /V "UploadUserActivities" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\System\CurrentControlSet\Control\Session Manager\Power" /V "HibernateEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /V "ShowHibernateOption" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /V "Value" /T "REG_SZ" /D Deny /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /V "SensorPermissionState" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /V "Status" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SYSTEM\Maps" /V "AutoUpdateEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\EdgeUpdate" /V "CreateDesktopShortcutDefault" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "PersonalizationReportingEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "ShowRecommendationsEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "HideFirstRunExperience" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "UserFeedbackAllowed" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "ConfigureDoNotTrack" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "AlternateErrorPagesEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "EdgeCollectionsEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "EdgeShoppingAssistantEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "MicrosoftEdgeInsiderPromotionEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "ShowMicrosoftRewards" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "WebWidgetAllowed" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "DiagnosticData" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "EdgeAssetDeliveryServiceEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "CryptoWalletEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "WalletDonationEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /V "AllowTelemetry" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /V "AllowTelemetry" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "ContentDeliveryAllowed" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEverEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338387Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338388Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338389Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353698Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SystemPaneSuggestionsEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /V "NumberOfSIUFInPeriod" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "NumberOfSIUFInPeriod" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /V "DoNotShowFeedbackNotifications" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V "DisableTailoredExperiencesWithDiagnosticData" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /V "DisabledByGroupPolicy" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /V "Disabled" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /V "DODownloadMode" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SYSTEM\CurrentControlSet\Control\echoote Assistance" /V "fAllowToGetHelp" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /V "EnthusiastMode" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /V "PeopleBand" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "LaunchTo" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SYSTEM\CurrentControlSet\Control\FileSystem" /V "LongPathsEnabled" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /V "SearchOrderConfig" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /V "SystemResponsiveness" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /V "NetworkThrottlingIndex" /T "REG_DWORD" /D "4294967295" /F
REG Add "HKCU\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /V "ClearPageFileAtShutdown" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\Ndu" /V "Start" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /V "IRPStackSize" /T "REG_DWORD" /D "30" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V "HideSCAMeetNow" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /V "ScoobeSystemSettingEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /V "Value" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /V "Value" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" /V "TurnOffWindowsCopilot" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot" /V "TurnOffWindowsCopilot" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /V "DisableAIDataAnalysis" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SYSTEM\CurrentControlSet\Control\Session Manager" /V "DisableWpbtExecution" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\System\GameConfigStore" /V "GameDVR_FSEBehavior" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\System\GameConfigStore" /V "GameDVR_Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\System\GameConfigStore" /V "GameDVR_HonorUserFSEBehaviorMode" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\System\GameConfigStore" /V "GameDVR_EFSEFeatureFlags" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /V "GlobalUserDisabled" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Microsoft\PolicyManager\current\device\Education" /V "IsEducationEnvironment" /T "REG_DWORD" /D "0" /F


ECHO .
ECHO ::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Microsoft Defender :::::
ECHO ::::::::::::::::::::::::::::::::::::::::
echo.

ECHO Disable Tamper Protection
REG Add "HKLM\Software\Microsoft\Windows Defender\Features" /V "TamperProtection" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows Defender\Features" /V "TamperProtection" /T "REG_DWORD" /D "0" /F

ECHO Disable System GuaRD Runtime Monitor Broker (when disabled, it might cause BSOD Critical Process Died)
REG Add "HKLM\System\CurrentControlSet\Services\SgrmBroker" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\System\CurrentControlSet\Services\SgrmBroker" /V "Start" /T "REG_DWORD" /D "4" /F

ECHO Disable Windows Defender Security Center
REG Add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\System\CurrentControlSet\Services\SecurityHealthService" /V "Start" /T "REG_DWORD" /D "4" /F

ECHO Disable Antivirus Notifications
REG Add "HKLM\Software\Microsoft\Windows Defender Security Center\Notifications" /V "DisableNotifications" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Notifications" /V "DisableEnhancedNotifications " /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Microsoft\Windows Defender Security Center\Notifications" /V "DisableNotifications" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender Security Center\Notifications" /V "DisableEnhancedNotifications " /T "REG_DWORD" /D "1" /F

ECHO Disable Security and Maitenance Notification
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /V "Enabled" /T "REG_DWORD" /D "0" /F

ECHO Disable Real-time protection
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender" /V "AllowFastServiceStartup" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender" /V "DisableAntiSpyware" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender" /V "DisableAntiVirus" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender" /V "DisableSpecialRunningModes" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender" /V "ServiceKeepAlive" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /V "MpEnablePus" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableBehaviorMonitoring" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableIOAVProtection" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableOnAccessProtection" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableRealtimeMonitoring" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableRoutinelyTakingAction" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableScanOnRealtimeEnable" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /V "DisableEnhancedNotifications" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /V "DisableBlockAtFirstSeen" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /V "SpynetReporting" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /V "SubmitSamplesConsent" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender" /V "AllowFastServiceStartup" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender" /V "DisableAntiSpyware" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender" /V "DisableAntiVirus" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender" /V "DisableSpecialRunningModes" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender" /V "ServiceKeepAlive" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\MpEngine" /V "MpEnablePus" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableBehaviorMonitoring" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableIOAVProtection" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableOnAccessProtection" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableRealtimeMonitoring" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableRoutinelyTakingAction" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableScanOnRealtimeEnable" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\Reporting" /V "DisableEnhancedNotifications" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\SpyNet" /V "DisableBlockAtFirstSeen" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\SpyNet" /V "SpynetReporting" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\SpyNet" /V "SubmitSamplesConsent" /T "REG_DWORD" /D "2" /F


ECHO Disable Logging
REG Add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /V "Start" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /V "Start" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /V "Start" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /V "Start" /T "REG_DWORD" /D "0" /F

ECHO Disable Tasks
SchTasks /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuaRD MDM policy Refresh" /Disable
SchTasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable
SchTasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable
SchTasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable
SchTasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable

ECHO Disable Systray icon
REG Delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /V "SecurityHealth" /F
REG Delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /V "SecurityHealth" /F
REG Delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /V "SecurityHealth" /F
REG Delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /V "SecurityHealth" /F

ECHO Remove Context menu
REG Delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /F
REG Delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /F
REG Delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /F

ECHO Disable Services
REG Add "HKLM\System\CurrentControlSet\Services\WdBoot" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\System\CurrentControlSet\Services\MDCoreSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\System\CurrentControlSet\Services\WdFilter" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\System\CurrentControlSet\Services\WdNisDrv" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\System\CurrentControlSet\Services\WdNisSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\System\CurrentControlSet\Services\WinDefend" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\System\CurrentControlSet\Services\WdBoot" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\System\CurrentControlSet\Services\MDCoreSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\System\CurrentControlSet\Services\WdFilter" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\System\CurrentControlSet\Services\WdNisDrv" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\System\CurrentControlSet\Services\WdNisSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\System\CurrentControlSet\Services\WinDefend" /V "Start" /T "REG_DWORD" /D "4" /F

ECHO Web Threat Defense Service (Phishing protection)
SC Stop "webthreatdefsvc"
SC Config "webthreatdefsvc" Start=Disabled

ECHO Web Threat Defense User Service (Phishing protection)
SC Stop "webthreatdefusersvc"
SC Config "webthreatdefusersvc" Start=Disabled

ECHO Disable Windows SmartScreen
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /V "SmartScreenEnabled" /T "REG_SZ" /D "Off" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /V "SmartScreenEnabled" /T "REG_SZ" /D "Off" /F 
REG Add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer" /V "SmartScreenEnabled" /T "REG_SZ" /D "Off" /F 
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /V "EnableWebContentEvaluation" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /V "EnableSmartScreen" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /V "SmartScreenEnabled" /T "REG_SZ" /D "Off" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /V "SmartScreenEnabled" /T "REG_SZ" /D "Off" /F 
REG Add "HKCU\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer" /V "SmartScreenEnabled" /T "REG_SZ" /D "Off" /F 
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /V "EnableWebContentEvaluation" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\System" /V "EnableSmartScreen" /T "REG_DWORD" /D "0" /F

ECHO Disable SmartScreen Filter in Microsoft Edge
REG Add "HKLM\Software\Microsoft\Edge\SmartScreenEnabled" /VE /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Edge\SmartScreenEnabled" /VE /T "REG_DWORD" /D "0" /F

ECHO Disable SmartScreen PUA in Microsoft Edge 
REG Add "HKLM\Software\Microsoft\Edge\SmartScreenPuaEnabled" /VE /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Edge\SmartScreenPuaEnabled" /VE /T "REG_DWORD" /D "0" /F

ECHO Disable Windows SmartScreen for Windows Store Apps
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\AppHost" /V "EnableWebContentEvaluation" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /V "EnableWebContentEvaluation" /T "REG_DWORD" /D "0" /F

ECHO Remove Smartscreen (to restore run "SFC /ScanNow")
TakeOwn /S "%computername%" /U "%username%" /F "%WinDir%\System32\smartscreen.exe"
icacls "%WinDir%\System32\smartscreen.exe" /grant:r %username%:f
TaskKill /IM "smartscreen.exe" /F
DEL "%WinDir%\System32\smartscreen.exe" /S /F /Q

ECHO Disable Smart App Control blocking legitimate apps
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /V "VerifiedAndReputablePolicyState" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender" /V "VerifiedAndReputablePolicyState" /T "REG_DWORD" /D "0" /F

ECHO Other Registries and finishing setup
REG Add "HKLM\Software\Microsoft\Windows Defender\Features" /V "TamperProtection" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\System\CurrentControlSet\Control\CI\Policy" /V "PUAProtection" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\System\CurrentControlSet\Control\CI\Policy" /V "DisableAntiSpyware" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\System\CurrentControlSet\Control\CI\Policy" /V "DisableAntiVirus" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V SettingsPageVisibility /T "REG_SZ" /D hide:home /F
REG Add "HKCU\Software\Microsoft\Windows Defender\Features" /V "TamperProtection" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\System\CurrentControlSet\Control\CI\Policy" /V "PUAProtection" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\System\CurrentControlSet\Control\CI\Policy" /V "DisableAntiSpyware" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\System\CurrentControlSet\Control\CI\Policy" /V "DisableAntiVirus" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V SettingsPageVisibility /T "REG_SZ" /D hide:home /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\Sense" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\WdNisSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\WdFilter" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\WinDefend" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\SamSs" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\wscsvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\SgrmBroker" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\SecurityHealthService" /V "Start" /T "REG_DWORD" /D "4" /F
NET Stop "Sense"
NET Stop "WdFilter"
NET Stop "WdNisSvc"
NET Stop "WinDefend"
REG Add "HKLM\SOFTWARE\Microsoft\Windows Defender" /V "DisableAntiVirus" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows Defender" /V "DisableAntiSpyware" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows Defender" /V "DisableRoutinelyTakingAction" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows Defender" /V "OneTimeSqmDataSent" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SpyNetReporting" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SubmitSamplesConsent" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableBehaviorMonitoring" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableOnAccessProtection" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableScanOnRealtimeEnable" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableRealtimeMonitoring" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows Defender\UX Configuration" /V "DisablePrivacyMode" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows Defender\Scan" /V "AutomaticallyCleanAfterScan" /T "REG_DWORD" /D "0" /F
SchTasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable
SchTasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable
SchTasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable
SchTasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable
REG Add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /V "DontOfferThroughWUAU" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /V "DontReportInfectionInformation" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisDrv" /V "Start" /T "REG_DWORD" /D "2" /F 
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WdBoot" /V "Start" /T "REG_DWORD" /D "2" /F 
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" /V "Start" /T "REG_DWORD" /D "2" /F
Regsvr32 /S /U "%ProgramFiles%\Windows Defender\shellext.dll"
REG Add "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /V "DisableAntiSpywareRealtimeProtection" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /V "DisableRealtimeMonitoring" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /V "DpaDisabled" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows Defender" /V "ProductStatus" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows Defender" /V "ManagedDefenderProductType" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /V "DontReportInfectionInformation" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\Sense" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\WdNisSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\WdFilter" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\WinDefend" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\SamSs" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\wscsvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\SgrmBroker" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\SecurityHealthService" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows Defender" /V "DisableAntiVirus" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows Defender" /V "DisableAntiSpyware" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows Defender" /V "DisableRoutinelyTakingAction" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows Defender" /V "OneTimeSqmDataSent" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SpyNetReporting" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SubmitSamplesConsent" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableBehaviorMonitoring" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableOnAccessProtection" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableScanOnRealtimeEnable" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableRealtimeMonitoring" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows Defender\UX Configuration" /V "DisablePrivacyMode" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows Defender\Scan" /V "AutomaticallyCleanAfterScan" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\MRT" /V "DontOfferThroughWUAU" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\MRT" /V "DontReportInfectionInformation" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WdNisDrv" /V "Start" /T "REG_DWORD" /D "2" /F 
REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WdBoot" /V "Start" /T "REG_DWORD" /D "2" /F 
REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WdFilter" /V "Start" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /V "DisableAntiSpywareRealtimeProtection" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /V "DisableRealtimeMonitoring" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /V "DpaDisabled" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows Defender" /V "ProductStatus" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows Defender" /V "ManagedDefenderProductType" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\MRT" /V "DontReportInfectionInformation" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /V "Start" /T "REG_DWORD" /D "4" /F

ECHO Disable Windows Firewall
REG Add "HKLM\SYSTEM\ControlSet001\Services\mpssvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\BFE" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /V "EnableFirewall" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /V "DisableNotifications" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /V "DoNotAllowExceptions" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /V "EnableFirewall" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /V "DisableNotifications" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /V "DoNotAllowExceptions" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /V "EnableFirewall" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /V "DisableNotifications" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /V "DoNotAllowExceptions" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\mpssvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\BFE" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /V "EnableFirewall" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /V "DisableNotifications" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /V "DoNotAllowExceptions" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /V "EnableFirewall" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /V "DisableNotifications" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /V "DoNotAllowExceptions" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /V "EnableFirewall" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /V "DisableNotifications" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /V "DoNotAllowExceptions" /T "REG_DWORD" /D "1" /F

ECHO disable watson malware reports
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /V "DisableGenericReports" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /V "DisableGenericReports" /T "REG_DWORD" /D "2" /F

ECHO disable malware diagnostic data 
REG Add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /V "DontReportInfectionInformation" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\MRT" /V "DontReportInfectionInformation" /T "REG_DWORD" /D "2" /F

ECHO Disable  setting override for reporting to Microsoft MAPS
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "LocalSettingOverrideSpynetReporting" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "LocalSettingOverrideSpynetReporting" /T "REG_DWORD" /D "0" /F

ECHO disable spynet Defender reporting
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SpynetReporting" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SpynetReporting" /T "REG_DWORD" /D "0" /F

ECHO do not send malware samples for further analysis
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SubmitSamplesConsent" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SubmitSamplesConsent" /T "REG_DWORD" /D "2" /F


ECHO .
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Auto-install subscribed/suggested apps :::::
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO .

REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "ContentDeliveryAllowed" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "FeatuechoanagementEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "OemPreInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEverEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SilentInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SoftLandingEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContentEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-310093Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338388Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338389Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338393Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353694Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353696Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContentEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SystemPaneSuggestionsEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /V "DODownloadMode" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Policies\Microsoft\Windows\DeliveryOptimization" /V "DODownloadMode" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Policies\Microsoft\PushToInstall" /V "DisablePushToInstall" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\Software\Policies\Microsoft\MRT" /V "DontOfferThroughWUAU" /T "REG_DWORD" /D "1" /F
REG Delete "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /F
REG Delete "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "ContentDeliveryAllowed" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "FeatuechoanagementEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "OemPreInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEverEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SilentInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SoftLandingEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContentEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-310093Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338388Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338389Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338393Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353694Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353696Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContentEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SystemPaneSuggestionsEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /V "DODownloadMode" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Policies\Microsoft\Windows\DeliveryOptimization" /V "DODownloadMode" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Policies\Microsoft\PushToInstall" /V "DisablePushToInstall" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Policies\Microsoft\MRT" /V "DontOfferThroughWUAU" /T "REG_DWORD" /D "1" /F
REG Delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /F
REG Delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /F


ECHO .
ECHO :::::::::::::::::::::::::::::::
ECHO ::::: Disabling BitLocker :::::
ECHO :::::::::::::::::::::::::::::::
ECHO .

REG Add "HKLM\SYSTEM\ControlSet001\Control\BitLocker" /V "PreventDeviceEncryption" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\BDESVC" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Control\BitLocker" /V "PreventDeviceEncryption" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\BDESVC" /V "Start" /T "REG_DWORD" /D "4" /F


ECHO .
ECHO :::::::::::::::::::::::::::::::
ECHO ::::: Disabling Chat Icon :::::
ECHO :::::::::::::::::::::::::::::::
ECHO .

REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows" /V "ChatIcon" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "TaskbarMn" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows" /V "ChatIcon" /T "REG_DWORD" /D "3" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "TaskbarMn" /T "REG_DWORD" /D "0" /F


ECHO .
ECHO :::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Hibernation :::::
ECHO :::::::::::::::::::::::::::::::::
ECHO .

powercfg.exe /hibernate off
powercfg /hibernate off
powercfg -h off
REG Add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /V "HiberbootEnabled" /T "REG_DWORD" /D "0" /F


ECHO .
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Windows Recovery Partition :::::
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::
ECHO .

reagentc /info
reagentc /Disable


ECHO .
ECHO ::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Reserved Storage :::::
ECHO ::::::::::::::::::::::::::::::::::::::
ECHO .

fsutil storagereserve query C:
DISM /Online /Set-ReservedStorageState /State:Disabled /Quiet /NoRestart
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /V "MiscPolicyInfo" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /V "PassedPolicy" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /V "ShippedWithReserves" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /V "MiscPolicyInfo" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /V "PassedPolicy" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /V "ShippedWithReserves" /T "REG_DWORD" /D "0" /F


ECHO .
ECHO ::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling NTFS Last Access :::::
ECHO ::::::::::::::::::::::::::::::::::::::
ECHO .

fsutil behavior set disablelastaccess 1


ECHO .
ECHO :::::::::::::::::::::::::::::::::
ECHO ::::: Enabling TRIM for SSD :::::
ECHO :::::::::::::::::::::::::::::::::
ECHO .

fsutil behavior set disabledeletenotify 0


ECHO .
ECHO :::::::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Windows Error Reporting :::::
ECHO :::::::::::::::::::::::::::::::::::::::::::::
ECHO .

REG Add "HKLM\SYSTEM\ControlSet001\Services\WerSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\WpnService" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\WpnUserService" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\WerSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\WpnService" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\WpnUserService" /V "Start" /T "REG_DWORD" /D "4" /F

ECHO Disable Microsoft Support Diagnostic Tool MSDT
REG Add "HKLM\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /V "DisableQueryechooteServer" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /V "EnableQueryechooteServer" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /V "DisableQueryechooteServer" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /V "EnableQueryechooteServer" /T "REG_DWORD" /D "0" /F

ECHO Disable System Debugger
REG Add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AeDebug" /V "Auto" /T "REG_SZ" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\AeDebug" /V "Auto" /T "REG_SZ" /D "0" /F

ECHO Disable Windows Error Reporting
REG Add "HKLM\Software\Microsoft\PCHealth\ErrorReporting" /V "DoReport" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /V "Disabled" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /V "Disabled" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /V "Disabled" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Microsoft\PCHealth\ErrorReporting" /V "DoReport" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /V "Disabled" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /V "Disabled" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Policies\Microsoft\Windows\Windows Error Reporting" /V "Disabled" /T "REG_DWORD" /D "1" /F

ECHO DefaultConsent / 1 - Always ask (default) / 2 - Parameters only / 3 - Parameters and safe data / 4 - All data
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /V "DefaultConsent" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /V "DefaultOverrideBehavior" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /V "DefaultConsent" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /V "DefaultOverrideBehavior" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting\Consent" /V "DefaultConsent" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting\Consent" /V "DefaultOverrideBehavior" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting\Consent" /V "DefaultConsent" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting\Consent" /V "DefaultOverrideBehavior" /T "REG_DWORD" /D "1" /F

ECHO 1 - Disable WER sending second-level data
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /V "DontSendAdditionalData" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /V "DontSendAdditionalData" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /V "DontSendAdditionalData" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /V "DontSendAdditionalData" /T "REG_DWORD" /D "1" /F

ECHO 1 - Disable WER crash dialogs, popups
REG Add "HKLM\Software\Microsoft\PCHealth\ErrorReporting" /V "ShowUI" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /V "DontShowUI" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /V "DontShowUI" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Microsoft\PCHealth\ErrorReporting" /V "ShowUI" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /V "DontShowUI" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /V "DontShowUI" /T "REG_DWORD" /D "1" /F

ECHO 1 - Disable WER logging
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /V "LoggingDisabled" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /V "LoggingDisabled" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /V "LoggingDisabled" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /V "LoggingDisabled" /T "REG_DWORD" /D "1" /F
SchTasks /Change /TN "Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" /Disable
SchTasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable

ECHO Windows Error Reporting Service
SC Stop "WerSvc"
SC Config "WerSvc" Start=Disabled


ECHO .
ECHO ::::::::::::::::::::::::::::::::::::
ECHO ::::: Windows Explorer Options :::::
ECHO ::::::::::::::::::::::::::::::::::::
ECHO .

ECHO Open File Explorer to This PC
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "LaunchTo" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "LaunchTo" /T "REG_DWORD" /D "1" /F

ECHO Disable recently used folders
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /V "ShowRecent" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /V "ShowRecent" /T "REG_DWORD" /D "0" /F

ECHO Disable frequently used folders
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /V "ShowFrequent" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /V "ShowFrequent" /T "REG_DWORD" /D "0" /F

ECHO Disable Show files from Office.com
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /V "ShowCloudFilesInQuickAccess" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /V "ShowCloudFilesInQuickAccess" /T "REG_DWORD" /D "0" /F

ECHO Disable Network Icon from Navigation Panel / Right in Nav Panel
REG Add "HKCR\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\ShellFolder" /V "Attributes" /T "REG_DWORD" /D "2962489444" /F

ECHO Remove Gallery from Navigation Pane in File Explorer
REG Add "HKLM\Software\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" /V "System.IsPinnedToNameSpaceTree" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" /V "System.IsPinnedToNameSpaceTree" /T "REG_DWORD" /D "0" /F

ECHO Remove 3D Folders from This PC
REG Delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /F
REG Delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /F

ECHO Remove Home (Quick access) from This PC
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /V "HubMode" /T "REG_DWORD" /D "1" /F
REG Delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /F
REG Delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /V "HubMode" /T "REG_DWORD" /D "1" /F
REG Delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /F
REG Delete "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /F

ECHO Show hidden files, folders and drives
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "Hidden" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "Hidden" /T "REG_DWORD" /D "1" /F

ECHO Show extensions for known file types
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "HideFileExt" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "HideFileExt" /T "REG_DWORD" /D "0" /F

ECHO Always show more details in copy dialog
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /V "EnthusiastMode" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /V "EnthusiastMode" /T "REG_DWORD" /D "1" /F


ECHO .
ECHO :::::::::::::::::::::::::::::::
ECHO ::::: Disabling Telemetry :::::
ECHO :::::::::::::::::::::::::::::::
ECHO .

REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Privacy" /V "TailoredExperiencesWithDiagnosticDataEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /V "HasAccepted" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Input\TIPC" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\InputPersonalization" /V "RestrictImplicitInkCollection" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\Software\Microsoft\InputPersonalization" /V "RestrictImplicitTextCollection" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\Software\Microsoft\InputPersonalization\TrainedDataStore" /V "HarvestContacts" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Personalization\Settings" /V "AcceptedPrivacyPolicy" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /V "AllowTelemetry" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" /V "ChatIcon" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "TaskbarMn" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /V "NoGenTicket" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /V "TailoredExperiencesWithDiagnosticDataEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /V "HasAccepted" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Input\TIPC" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\InputPersonalization" /V "RestrictImplicitInkCollection" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Microsoft\InputPersonalization" /V "RestrictImplicitTextCollection" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /V "HarvestContacts" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Personalization\Settings" /V "AcceptedPrivacyPolicy" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /V "AllowTelemetry" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\dmwappushservice" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" /V "ChatIcon" /T "REG_DWORD" /D "3" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "TaskbarMn" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /V "NoGenTicket" /T "REG_DWORD" /D "1" /F
SchTasks /Change /Disable /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
SchTasks /Change /Disable /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
SchTasks /Change /Disable /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
SchTasks /Change /Disable /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
SchTasks /Change /Disable /TN "\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents"
SchTasks /Change /Disable /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem"
SchTasks /Change /Disable /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
REG Add "HKLM\SOFTWARE\Microsoft\MediaPlayer\Preferences" /V "UsageTracking" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /V "UsageTracking" /T "REG_DWORD" /D "0" /F
SC Stop "WMPNetworkSvc"
SC Config "WMPNetworkSvc" Start=Disabled
SETX POWERSHELL_TELEMETRY_OPTOUT 1
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\15.0\osm" /V "enablefileobfuscation" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\15.0\osm" /V "enablelogging" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\15.0\osm" /V "enableupload" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common" /V "qmenable" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common" /V "sendcustomerdata" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common" /V "updatereliabilitydata" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" /V "enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" /V "includescreenshot" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\internet" /V "useonlinecontent" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\ptwatson" /V "ptwoptin" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm" /V "enablefileobfuscation" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm" /V "enablelogging" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm" /V "enableupload" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "accesssolution" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "olksolution" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "onenotesolution" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "pptsolution" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "projectsolution" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "publishersolution" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "visiosolution" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "wdsolution" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "xlsolution" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "agave" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "appaddins" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "comaddins" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "documentfiles" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "templatefiles" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" /V "blockcontentexecutionfrominternet" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /V "level" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" /V "blockcontentexecutionfrominternet" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\word\security" /V "blockcontentexecutionfrominternet" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\osm" /V "enablefileobfuscation" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\osm" /V "enablelogging" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\osm" /V "enableupload" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common" /V "qmenable" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common" /V "sendcustomerdata" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common" /V "updatereliabilitydata" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" /V "enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" /V "includescreenshot" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\internet" /V "useonlinecontent" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\ptwatson" /V "ptwoptin" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm" /V "enablefileobfuscation" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm" /V "enablelogging" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm" /V "enableupload" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "accesssolution" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "olksolution" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "onenotesolution" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "pptsolution" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "projectsolution" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "publishersolution" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "visiosolution" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "wdsolution" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "xlsolution" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "agave" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "appaddins" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "comaddins" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "documentfiles" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "templatefiles" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" /V "blockcontentexecutionfrominternet" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /V "level" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" /V "blockcontentexecutionfrominternet" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security" /V "blockcontentexecutionfrominternet" /T "REG_DWORD" /D "0" /F


ECHO .
ECHO ::::::::::::::::::::::::::::::
ECHO ::::: Disabling OneDrive :::::
ECHO ::::::::::::::::::::::::::::::
ECHO .

ECHO Killing onedrive
TaskKill /F /IM "OneDrive.exe"

ECHO Running OneDrive uninstaller
if exist %SystemRoot%\System32\OneDriveSetup.exe (
	start /wait %SystemRoot%\System32\OneDriveSetup.exe /uninstall
) else (
	start /wait %SystemRoot%\SysWOW64\OneDriveSetup.exe /uninstall
)

ECHO Deleting OneDrive scheduled tasks
for /F "tokens=1 delims=," %%x in ('schtasks /Query /Fo csv ^| find "OneDrive"') do schtasks /Delete /TN %%x /F

ECHO Removing OneDrive shortcuts
DEL "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Microsoft OneDrive.lnk" /S /F /Q
DEL "%APPDATA%\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" /S /F /Q
DEL "%USERPROFILE%\Links\OneDrive.lnk" /S /F /Q

ECHO Removing OneDrive related directories
RD "%UserProfile%\OneDrive" /Q /S 
RD "%SystemDrive%\OneDriveTemp" /Q /s
RD "%LocalAppData%\Microsoft\OneDrive" /Q /s
RD "%ProgramData%\Microsoft OneDrive" /Q /s

ECHO Removing related registry folders
REG Delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4308-9B53-224DE2ED1FE6}" /F
REG Delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4308-9B53-224DE2ED1FE6}" /F

ECHO Disabling onesync
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\OneSyncSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\OneSyncSvc_402ac" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /V "DisableFileSyncNGSC" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /V "DisableFileSync" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /V "DisableMeteredNetworkFileSync" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /V "DisableLibrariesDefaultSaveToOneDrive" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Microsoft\OneDrive" /V "DisablePersonalSync" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SYSTEM\CurrentControlSet\Services\OneSyncSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\CurrentControlSet\Services\OneSyncSvc_402ac" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /V "DisableFileSyncNGSC" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /V "DisableFileSync" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /V "DisableMeteredNetworkFileSync" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /V "DisableLibrariesDefaultSaveToOneDrive" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Microsoft\OneDrive" /V "DisablePersonalSync" /T "REG_DWORD" /D "2" /F

ECHO Removing onedrive from explorer/quick access
REG Add "HKCR\CLSID\{018D5C66-4533-4308-9B53-224DE2ED1FE6}" /V "System.IsPinnedToNameSpaceTree" /T "REG_DWORD" /D "0" /F
REG Add "HKCR\Wow6432Node\{018D5C66-4533-4308-9B53-224DE2ED1FE6}" /V "System.IsPinnedToNameSpaceTree" /T "REG_DWORD" /D "0" /F


ECHO .
ECHO ::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling location services  :::::
ECHO ::::::::::::::::::::::::::::::::::::::::
ECHO .

REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /V "DisableWindowsLocationProvider" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /V "DisableLocationScripting" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /V "DisableLocation" /D "1" /T "REG_DWORD" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /V "DisableWindowsLocationProvider" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /V "DisableLocationScripting" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /V "DisableLocation" /D "1" /T "REG_DWORD" /F


ECHO .
ECHO ::::::::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Cloud Voice Recognation  :::::
ECHO ::::::::::::::::::::::::::::::::::::::::::::::
ECHO .

REG Add "HKLM\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /V "HasAccepted" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /V "HasAccepted" /T "REG_DWORD" /D "0" /F


ECHO .
ECHO ::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Bing in Start Menu :::::
ECHO ::::::::::::::::::::::::::::::::::::::::
ECHO .

REG Add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /V "ShowRunAsDifferentUserInStart" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /V "DisableSearchBoxSuggestions" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /V "ShowRunAsDifferentUserInStart" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /V "DisableSearchBoxSuggestions" /T "REG_DWORD" /D "1" /F


ECHO .
ECHO :::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Opting out from Windows privacy consent :::::
ECHO :::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO .

REG Add "HKLM\SOFTWARE\Microsoft\Personalization\Settings" /V "AcceptedPrivacyPolicy" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /V "AcceptedPrivacyPolicy" /T "REG_DWORD" /D "0" /F


ECHO .
ECHO ::::::::::::::::::::::::::::
ECHO ::::: Disabling Search :::::
ECHO ::::::::::::::::::::::::::::
ECHO .

REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Search" /V "BingSearchEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Search" /V "CortanaEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowCloudSearch" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchUseWeb" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchUseWebOverMeteredConnections" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "DisableWebSearch" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowCortanaAboveLock" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\services\TermServicentVersion\Search" /V "AllowCortana" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowCortana" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowSearchToUseLocation" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowCortana" /T "REG_DWORD" /D "0" /F 
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowSearchToUseLocation" /T "REG_DWORD" /D "0" /F 
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchPrivacy" /T "REG_DWORD" /D "3" /F 
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchUseWeb" /T "REG_DWORD" /D "0" /F 
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchUseWebOverMeteredConnections" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "DisableWebSearch" /T "REG_DWORD" /D "1" /F 
REG Add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" /V "value" /T "REG_DWORD" /D "0" /F 
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "CortanaEnabled" /T "REG_DWORD" /D "0" /F 
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "BingSearchEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "CanCortanaBeEnabled" /T "REG_DWORD" /D "0" /F 
REG Add "HKLM\SOFTWARE\Microsoft\Personalization\Settings" /V "AcceptedPrivacyPolicy" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "DeviceHistoryEnabled" /T "REG_DWORD" /D "0" /F 
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "HistoryViewEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /V "BingSearchEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /V "CortanaEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowCloudSearch" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchUseWeb" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchUseWebOverMeteredConnections" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "DisableWebSearch" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowCortanaAboveLock" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SYSTEM\CurrentControlSet\services\TermServicentVersion\Search" /V "AllowCortana" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowCortana" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowSearchToUseLocation" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowCortana" /T "REG_DWORD" /D "0" /F 
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowSearchToUseLocation" /T "REG_DWORD" /D "0" /F 
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchPrivacy" /T "REG_DWORD" /D "3" /F 
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchUseWeb" /T "REG_DWORD" /D "0" /F 
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchUseWebOverMeteredConnections" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "DisableWebSearch" /T "REG_DWORD" /D "1" /F 
REG Add "HKCU\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" /V "value" /T "REG_DWORD" /D "0" /F 
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "CortanaEnabled" /T "REG_DWORD" /D "0" /F 
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "BingSearchEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "CanCortanaBeEnabled" /T "REG_DWORD" /D "0" /F 
REG Add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /V "AcceptedPrivacyPolicy" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "DeviceHistoryEnabled" /T "REG_DWORD" /D "0" /F 
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "HistoryViewEnabled" /T "REG_DWORD" /D "0" /F


ECHO .
ECHO :::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling DevHome and Outlook :::::
ECHO :::::::::::::::::::::::::::::::::::::::::
ECHO .

REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\OutlookUpdate" /V "workCompleted" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\DevHomeUpdate" /V "workCompleted" /T "REG_DWORD" /D "1" /F
REG Delete "HKLM\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate" /F
REG Delete "HKLM\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\OutlookUpdate" /V "workCompleted" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\DevHomeUpdate" /V "workCompleted" /T "REG_DWORD" /D "1" /F
REG Delete "HKCU\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate" /F
REG Delete "HKCU\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate" /F


ECHO .
ECHO ::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Sponsored apps :::::
ECHO ::::::::::::::::::::::::::::::::::::
ECHO .

REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "OemPreInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SilentInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V "DisableWindowsConsumerFeatures" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "ContentDeliveryAllowed" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "FeatureManagementEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "OemPreInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEverEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SoftLandingEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContentEnabled/T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-310093Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338388Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338389Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338393Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353694Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353696Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContentEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SystemPaneSuggestionsEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\PushToInstall" /V "DisablePushToInstall" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /V "DontOfferThroughWUAU" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V "DisableConsumerAccountStateContent" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V "DisableCloudOptimizedContent" /T "REG_DWORD" /D "1" /F
REG Delete "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /F
REG Delete "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "OemPreInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SilentInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V "DisableWindowsConsumerFeatures" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "ContentDeliveryAllowed" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "FeatureManagementEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "OemPreInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEverEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SoftLandingEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContentEnabled/T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-310093Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338388Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338389Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338393Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353694Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353696Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContentEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SystemPaneSuggestionsEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\PushToInstall" /V "DisablePushToInstall" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\MRT" /V "DontOfferThroughWUAU" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V "DisableConsumerAccountStateContent" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V "DisableCloudOptimizedContent" /T "REG_DWORD" /D "1" /F
REG Delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /F
REG Delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /F


ECHO .
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Deleting App Compatibility Appraiser and Assistant :::::
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO .

REG Delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0600DD45-FAF2-4131-A006-0B17509B9F78}" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /V "DisablePCA" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PcaSvc" /V "Start" /T "REG_DWORD" /D "2" /F
REG Delete "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0600DD45-FAF2-4131-A006-0B17509B9F78}" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /V "DisablePCA" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SYSTEM\CurrentControlSet\Services\PcaSvc" /V "Start" /T "REG_DWORD" /D "2" /F


ECHO .
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Deleting Customer Experiment Improvement Program :::::
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO .

REG Delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{4738DE7A-BCC1-4E2D-B1B0-CADB044BFA81}" /F
REG Delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{6FAC31FA-4A85-4E64-BFD5-2154FF4594B3}" /F
REG Delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{FC931F16-B50A-472E-B061-B6F79A71EF59}" /F
REG Delete "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{4738DE7A-BCC1-4E2D-B1B0-CADB044BFA81}" /F
REG Delete "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{6FAC31FA-4A85-4E64-BFD5-2154FF4594B3}" /F
REG Delete "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{FC931F16-B50A-472E-B061-B6F79A71EF59}" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /V "CEIPEnable" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client" /V "CEIP" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient" /V "CorporateSQMURL" /T "REG_SZ" /D "0.0.0.0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /V "CEIPEnable" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Messenger\Client" /V "CEIP" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\SQMClient" /V "CorporateSQMURL" /T "REG_SZ" /D "0.0.0.0" /F


ECHO .
ECHO :::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Deleting Program Data Updater :::::
ECHO :::::::::::::::::::::::::::::::::::::::::
ECHO .

REG Delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0671EB05-7D95-4153-A32B-1426B9FE61DB}" /F
REG Delete "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0671EB05-7D95-4153-A32B-1426B9FE61DB}" /F


ECHO .
ECHO ::::::::::::::::::::::::::::
ECHO ::::: Disabling Recall :::::
ECHO ::::::::::::::::::::::::::::
ECHO .

DISM /Online /Disable-Feature /FeatureName:Recall /Quiet /NoRestart


ECHO .
ECHO ::::::::::::::::::::::::::::::::::
ECHO ::::: Deleting autochk proxy :::::
ECHO ::::::::::::::::::::::::::::::::::
ECHO .

REG Delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{87BF85F4-2CE1-4160-96EA-52F554AA28A2}" /F
REG Delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{8A9C643C-3D74-4099-B6BD-9C6D170898B1}" /F
REG Delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{E3176A65-4E44-4ED3-AA73-3283660ACB9C}" /F
REG Delete "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{87BF85F4-2CE1-4160-96EA-52F554AA28A2}" /F
REG Delete "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{8A9C643C-3D74-4099-B6BD-9C6D170898B1}" /F
REG Delete "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{E3176A65-4E44-4ED3-AA73-3283660ACB9C}" /F


ECHO .
ECHO ::::::::::::::::::::::::::
ECHO ::::: Disabling XBOX :::::
ECHO ::::::::::::::::::::::::::
ECHO .

REG Add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /V "value" /T "REG_SZ" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /V AllowGameDVR /T "REG_DWORD" /D "0" /F
REG Add "HKLM\System\GameConfigStore" /V "GameDVR_Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /V "value" /T "REG_SZ" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" /V "ActivationType" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\XboxNetApiSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\XblGameSave" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\XblAuthManager" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\xbgm" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\XboxGipSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /V "value" /T "REG_SZ" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /V AllowGameDVR /T "REG_DWORD" /D "0" /F
REG Add "HKCU\System\GameConfigStore" /V "GameDVR_Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /V "value" /T "REG_SZ" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" /V "ActivationType" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\XboxNetApiSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\XblGameSave" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\XblAuthManager" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\xbgm" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\XboxGipSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\System\GameConfigStore" /V "GameDVR_Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\System\GameConfigStore" /V "GameDVR_FSEBehaviorMode" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\System\GameConfigStore" /V "GameDVR_HonorUserFSEBehaviorMode" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\System\GameConfigStore" /V "GameDVR_DXGIHonorFSEWindowsCompatible" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\System\GameConfigStore" /V "GameDVR_EFSEFeatureFlags" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\System\GameConfigStore" /V "GameDVR_Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\System\GameConfigStore" /V "GameDVR_FSEBehaviorMode" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\System\GameConfigStore" /V "GameDVR_HonorUserFSEBehaviorMode" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\System\GameConfigStore" /V "GameDVR_DXGIHonorFSEWindowsCompatible" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\System\GameConfigStore" /V "GameDVR_EFSEFeatureFlags" /T "REG_DWORD" /D "0" /F


ECHO .
ECHO :::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Sync Settings :::::
ECHO :::::::::::::::::::::::::::::::::::
ECHO .

REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /V "SyncPolicy" /T "REG_DWORD" /D "5" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\PackageState" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableSettingSync" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableSettingSyncUserOverride" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableAppSyncSettingSync" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableAppSyncSettingSyncUserOverride" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableApplicationSettingSync" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableApplicationSettingSyncUserOverride" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableCredentialsSettingSync" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableCredentialsSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableDesktopThemeSettingSync" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableDesktopThemeSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisablePersonalizationSettingSync" /T "REG_DWORD" /D "2" /F 
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisablePersonalizationSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableStartLayoutSettingSync" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableStartLayoutSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableSyncOnPaidNetwork" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableWebBrowserSettingSync" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableWebBrowserSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableWindowsSettingSync" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableWindowsSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /V "SyncPolicy" /T "REG_DWORD" /D "5" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\PackageState" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableSettingSync" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableSettingSyncUserOverride" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableAppSyncSettingSync" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableAppSyncSettingSyncUserOverride" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableApplicationSettingSync" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableApplicationSettingSyncUserOverride" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableCredentialsSettingSync" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableCredentialsSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableDesktopThemeSettingSync" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableDesktopThemeSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisablePersonalizationSettingSync" /T "REG_DWORD" /D "2" /F 
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisablePersonalizationSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableStartLayoutSettingSync" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableStartLayoutSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableSyncOnPaidNetwork" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableWebBrowserSettingSync" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableWebBrowserSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableWindowsSettingSync" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableWindowsSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F


ECHO .
ECHO :::::::::::::::::::::::::::::
ECHO ::::: Disabling Hyper-V :::::
ECHO :::::::::::::::::::::::::::::
ECHO .

REG Add "HKLM\SYSTEM\ControlSet001\Services\HvHost" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\vmickvpexchange" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\vmicguestinterface" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\vmicshutdown" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\vmicheartbeat" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\vmicvmsession" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\vmicrdv" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\vmictimesync" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\vmicvss" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\HvHost" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\vmickvpexchange" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\vmicguestinterface" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\vmicshutdown" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\vmicheartbeat" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\vmicvmsession" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\vmicrdv" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\vmictimesync" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\vmicvss" /V "Start" /T "REG_DWORD" /D "4" /F


ECHO .
ECHO ::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Remote Desktop :::::
ECHO ::::::::::::::::::::::::::::::::::::
ECHO .

REG Add "HKLM\SYSTEM\ControlSet001\Services\RasAuto" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\RasMan" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\SessionEnv" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\TermService" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\UmRdpService" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\RemoteRegistry" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\RpcLocator" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\RasAuto" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\RasMan" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\SessionEnv" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\TermService" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\UmRdpService" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\RemoteRegistry" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\RpcLocator" /V "Start" /T "REG_DWORD" /D "4" /F


ECHO .
ECHO ::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Smart CaRD :::::
ECHO ::::::::::::::::::::::::::::::::
ECHO .

REG Add "HKLM\SYSTEM\ControlSet001\Services\SCardSvr" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\ScDeviceEnum" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\SCPolicySvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\ControlSet001\Services\CertPropSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\SCardSvr" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\ScDeviceEnum" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\SCPolicySvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\CertPropSvc" /V "Start" /T "REG_DWORD" /D "4" /F


ECHO .
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Handwriting, inking and contacts :::::
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO .

REG Add "HKLM\Software\Policies\Microsoft\InputPersonalization" /V "RestrictImplicitInkCollection" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /V "RestrictImplicitInkCollection" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /V "PreventHandwritingErrorReports" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\Software\Policies\Microsoft\Windows\TabletPC" /V "PreventHandwritingDataSharing" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /V "PreventHandwritingDataSharing" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /V "AllowInputPersonalization" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /V "HarvestContacts" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Policies\Microsoft\InputPersonalization" /V "RestrictImplicitInkCollection" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization" /V "RestrictImplicitInkCollection" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /V "PreventHandwritingErrorReports" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\Software\Policies\Microsoft\Windows\TabletPC" /V "PreventHandwritingDataSharing" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /V "PreventHandwritingDataSharing" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization" /V "AllowInputPersonalization" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /V "HarvestContacts" /T "REG_DWORD" /D "0" /F


ECHO .
ECHO :::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling app launch tracking :::::
ECHO :::::::::::::::::::::::::::::::::::::::::
ECHO .

REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "Start_TrackProgs" /D "0" /T "REG_DWORD" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "Start_TrackProgs" /D "0" /T "REG_DWORD" /F


ECHO .
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Changing data usage and limits to manual for compatibility :::::
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO .

REG Add "HKLM\SYSTEM\ControlSet001\Services\DusmSvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKCU\SYSTEM\ControlSet001\Services\DusmSvc" /V "Start" /T "REG_DWORD" /D "3" /F


ECHO .
ECHO :::::::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling diagnostics and privacy :::::
ECHO :::::::::::::::::::::::::::::::::::::::::::::
ECHO .

REG Add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /V "DiagnosticErrorText" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /V "DiagnosticErrorText" /T "REG_SZ" /D "" /F
REG Add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /V "DiagnosticLinkText" /T "REG_SZ" /D "" /F
REG Add "HKLM\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /V "EnabledV9" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /V "DisableInventory" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /V "DisableUAR" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /V "NoLockScreenCamera" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Input\TIPC" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /V "DiagnosticErrorText" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /V "DiagnosticErrorText" /T "REG_SZ" /D "" /F
REG Add "HKCU\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /V "DiagnosticLinkText" /T "REG_SZ" /D "" /F
REG Add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /V "EnabledV9" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /V "DisableInventory" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /V "DisableUAR" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Personalization" /V "NoLockScreenCamera" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Input\TIPC" /V "Enabled" /T "REG_DWORD" /D "0" /F
SC Stop "DiagTrack"
SC Stop "dmwappushservice"
SC Delete "DiagTrack"
SC Delete "dmwappushservice"


ECHO .
ECHO :::::::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling windows insider experiments :::::
ECHO :::::::::::::::::::::::::::::::::::::::::::::
ECHO .

REG Add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" /V "AllowExperimentation" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" /V "value" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\PolicyManager\current\device\System" /V "AllowExperimentation" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" /V "value" /T "REG_DWORD" /D "0" /F


ECHO .
ECHO ::::::::::::::::::::::::::::::::
ECHO ::::: Changing Apps Access :::::
ECHO ::::::::::::::::::::::::::::::::
ECHO .

ECHO account info
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /V "Value" /T "REG_SZ" /D "Deny" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /V "Value" /T "REG_SZ" /D "Deny" /F

ECHO radios
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /V "Value" /T "REG_SZ" /D "Deny" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /V "Value" /T "REG_SZ" /D "Deny" /F

ECHO diagnostic
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" /V "Value" /T "REG_SZ" /D "Deny" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" /V "Value" /T "REG_SZ" /D "Deny" /F

ECHO contacts
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" /V "Value" /T "REG_SZ" /D "Deny" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" /V "Value" /T "REG_SZ" /D "Deny" /F

ECHO calendar
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /V "Value" /T "REG_SZ" /D "Deny" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /V "Value" /T "REG_SZ" /D "Deny" /F

ECHO call history
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" /V "Value" /T "REG_SZ" /D "Deny" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" /V "Value" /T "REG_SZ" /D "Deny" /F

ECHO email
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" /V "Value" /T "REG_SZ" /D "Deny" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" /V "Value" /T "REG_SZ" /D "Deny" /F

ECHO tasks
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E390DF20-07DF-446D-B962-F5C953072741}" /V "Value" /T "REG_SZ" /D "Deny" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E390DF20-07DF-446D-B962-F5C953072741}" /V "Value" /T "REG_SZ" /D "Deny" /F


ECHO location device hardening
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /V "GlobalUserDisabled" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /V "DisableOnline" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Browser" /V "AllowAddressBarDropdown" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Privacy" /V "EnableEncryptedMediaExtensions" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\SettingSync" /V "SyncPolicy" /T "REG_DWORD" /D "5" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /V "ModelDownloadAllowed" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /V "DoNotShowFeedbackNotifications" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /V "MaxTelemetryAllowed" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Speech" /V "AllowSpeechModelUpdate" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /V "DisableSettingSync" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /V "DisableSettingSyncUserOverride" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SpyNetReporting" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SubmitSamplesConsent" /T "REG_DWORD" /D "2" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /V "DontReportInfectionInformation" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /V "DontOfferThroughWUAU" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /V "DisableAntiSpyware" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SilentInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SoftLandingEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows\ScheduledDiagnostics" /V "EnabledExecution" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\OneDrive" /V "PreventNetworkTrafficPreUserSignIn" /T "REG_DWORD" /D "1" /F
REG Add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Experience" /V "AllowCortana" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Experience" /V "AllowTailoredExperiencesWithDiagnosticData" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /V "Start" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /V "Start" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /V "EnableVirtualizationBasedSecurity" /T "REG_DWORD" /D "0" /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /V "HVCIMATRequired" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /V "GlobalUserDisabled" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\WMDRM" /V "DisableOnline" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Microsoft\PolicyManager\current\device\Browser" /V "AllowAddressBarDropdown" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Privacy" /V "EnableEncryptedMediaExtensions" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync" /V "SyncPolicy" /T "REG_DWORD" /D "5" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /V "Enabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /V "ModelDownloadAllowed" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /V "DoNotShowFeedbackNotifications" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /V "MaxTelemetryAllowed" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Speech" /V "AllowSpeechModelUpdate" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Policies\Microsoft\Windows\SettingSync" /V "DisableSettingSync" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\Software\Policies\Microsoft\Windows\SettingSync" /V "DisableSettingSyncUserOverride" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SpyNetReporting" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SubmitSamplesConsent" /T "REG_DWORD" /D "2" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\MRT" /V "DontReportInfectionInformation" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\MRT" /V "DontOfferThroughWUAU" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender" /V "DisableAntiSpyware" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SilentInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SoftLandingEnabled" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\Windows\ScheduledDiagnostics" /V "EnabledExecution" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\OneDrive" /V "PreventNetworkTrafficPreUserSignIn" /T "REG_DWORD" /D "1" /F
REG Add "HKCU\SOFTWARE\Microsoft\PolicyManager\current\device\Experience" /V "AllowCortana" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Microsoft\PolicyManager\current\device\Experience" /V "AllowTailoredExperiencesWithDiagnosticData" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /V "Start" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /V "Start" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /V "EnableVirtualizationBasedSecurity" /T "REG_DWORD" /D "0" /F
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /V "HVCIMATRequired" /T "REG_DWORD" /D "0" /F


ECHO .
ECHO ::::::::::::::::::::::::::::
ECHO ::::: Setting Services :::::
ECHO ::::::::::::::::::::::::::::
ECHO .

ECHO Manual Services
SC Config "AppMgmt" Start=Demand
SC Config "AppMgmt_*" Start=Demand
SC Config "AppReadiness" Start=Demand
SC Config "AppReadiness_*" Start=Demand
SC Config "AppXSvc" Start=Demand
SC Config "AppXSvc_*" Start=Demand
SC Config "Appinfo" Start=Demand
SC Config "Appinfo_*" Start=Demand
SC Config "BITS" Start=Demand
SC Config "BITS_*" Start=Demand
SC Config "BTAGService" Start=Demand
SC Config "BTAGService_*" Start=Demand
SC Config "BluetoothUserService" Start=Demand
SC Config "BluetoothUserService_*" Start=Demand
SC Config "Browser" Start=Demand
SC Config "Browser_*" Start=Demand
SC Config "BthAvctpSvc" Start=Demand
SC Config "BthAvctpSvc_*" Start=Demand
SC Config "COMSysApp" Start=Demand
SC Config "COMSysApp_*" Start=Demand
SC Config "CaptureService" Start=Demand
SC Config "CaptureService_*" Start=Demand
SC Config "ClipSVC" Start=Demand
SC Config "ClipSVC_*" Start=Demand
SC Config "CredentialEnrollmentManagerUserSvc" Start=Demand
SC Config "CredentialEnrollmentManagerUserSvc_*" Start=Demand
SC Config "DcpSvc" Start=Demand
SC Config "DcpSvc_*" Start=Demand
SC Config "DeviceAssociationService" Start=Demand
SC Config "DeviceAssociationService_*" Start=Demand
SC Config "DeviceInstall" Start=Demand
SC Config "DeviceInstall_*" Start=Demand
SC Config "DevicesFlowUserSvc" Start=Demand
SC Config "DevicesFlowUserSvc_*" Start=Demand
SC Config "DispBrokerDesktopSvc" Start=Demand
SC Config "DispBrokerDesktopSvc_*" Start=Demand
SC Config "DisplayEnhancementService" Start=Demand
SC Config "DisplayEnhancementService_*" Start=Demand
SC Config "DsmSvc" Start=Demand
SC Config "DsmSvc_*" Start=Demand
SC Config "EFS" Start=Demand
SC Config "EFS_*" Start=Demand
SC Config "EapHost" Start=Demand
SC Config "EapHost_*" Start=Demand
SC Config "EventSystem" Start=Demand
SC Config "EventSystem_*" Start=Demand
SC Config "FontCache" Start=Demand
SC Config "FontCache_*" Start=Demand
SC Config "FrameServer" Start=Demand
SC Config "FrameServerMonitor" Start=Demand
SC Config "FrameServerMonitor_*" Start=Demand
SC Config "FrameServer_*" Start=Demand
SC Config "GraphicsPerfSvc" Start=Demand
SC Config "GraphicsPerfSvc_*" Start=Demand
SC Config "HomeGroupListener" Start=Demand
SC Config "HomeGroupListener_*" Start=Demand
SC Config "HomeGroupProvider" Start=Demand
SC Config "HomeGroupProvider_*" Start=Demand
SC Config "IEEtwCollectorService" Start=Demand
SC Config "IEEtwCollectorService_*" Start=Demand
SC Config "InstallService" Start=Demand
SC Config "InstallService_*" Start=Demand
SC Config "IpxlatCfgSvc" Start=Demand
SC Config "IpxlatCfgSvc_*" Start=Demand
SC Config "KeyIso" Start=Demand
SC Config "KeyIso_*" Start=Demand
SC Config "KtmRm" Start=Demand
SC Config "KtmRm_*" Start=Demand
SC Config "LicenseManager" Start=Demand
SC Config "LicenseManager_*" Start=Demand
SC Config "LocalKdc" Start=Demand
SC Config "LocalKdc_*" Start=Demand
SC Config "LxpSvc" Start=Demand
SC Config "LxpSvc_*" Start=Demand
SC Config "MSDTC" Start=Demand
SC Config "MSDTC_*" Start=Demand
SC Config "NPSMSvc" Start=Demand
SC Config "NPSMSvc_*" Start=Demand
SC Config "NcbService" Start=Demand
SC Config "NcbService_*" Start=Demand
SC Config "NetSetupSvc" Start=Demand
SC Config "NetSetupSvc_*" Start=Demand
SC Config "Netman" Start=Demand
SC Config "Netman_*" Start=Demand
SC Config "NlaSvc" Start=Demand
SC Config "NlaSvc_*" Start=Demand
SC Config "PNRPAutoREG" Start=Demand
SC Config "PNRPAutoREG_*" Start=Demand
SC Config "PNRPsvc" Start=Demand
SC Config "PNRPsvc_*" Start=Demand
SC Config "PcaSvc" Start=Demand
SC Config "PcaSvc_*" Start=Demand
SC Config "PerfHost" Start=Demand
SC Config "PerfHost_*" Start=Demand
SC Config "PlugPlay" Start=Demand
SC Config "PlugPlay_*" Start=Demand
SC Config "PrintNotify" Start=Demand
SC Config "PrintNotify_*" Start=Demand
SC Config "QWAVE" Start=Demand
SC Config "QWAVE_*" Start=Demand
SC Config "RasMan" Start=Demand
SC Config "RasMan_*" Start=Demand
SC Config "RmSvc" Start=Demand
SC Config "RmSvc_*" Start=Demand
SC Config "SharedRealitySvc" Start=Demand
SC Config "SharedRealitySvc_*" Start=Demand
SC Config "ShellHWDetection" Start=Demand
SC Config "ShellHWDetection_*" Start=Demand
SC Config "SstpSvc" Start=Demand
SC Config "SstpSvc_*" Start=Demand
SC Config "StorSvc" Start=Demand
SC Config "StorSvc_*" Start=Demand
SC Config "TabletInputService" Start=Demand
SC Config "TabletInputService_*" Start=Demand
SC Config "Themes" Start=Demand
SC Config "Themes_*" Start=Demand
SC Config "TimeBroker" Start=Demand
SC Config "TimeBrokerSvc" Start=Demand
SC Config "TimeBrokerSvc_*" Start=Demand
SC Config "TimeBroker_*" Start=Demand
SC Config "TokenBroker" Start=Demand
SC Config "TokenBroker_*" Start=Demand
SC Config "TrustedInstaller" Start=Demand
SC Config "TrustedInstaller_*" Start=Demand
SC Config "UI0Detect" Start=Demand
SC Config "UI0Detect_*" Start=Demand
SC Config "UdkUserSvc" Start=Demand
SC Config "UdkUserSvc_*" Start=Demand
SC Config "UsoSvc" Start=Demand
SC Config "UsoSvc_*" Start=Demand
SC Config "VacSvc" Start=Demand
SC Config "VacSvc_*" Start=Demand
SC Config "VaultSvc" Start=Demand
SC Config "VaultSvc_*" Start=Demand
SC Config "W32Time" Start=Demand
SC Config "W32Time_*" Start=Demand
SC Config "WSService" Start=Demand
SC Config "WSService_*" Start=Demand
SC Config "WbioSrvc" Start=Demand
SC Config "WbioSrvc_*" Start=Demand
SC Config "WcsPlugInService" Start=Demand
SC Config "WcsPlugInService_*" Start=Demand
SC Config "WdNisSvc" Start=Demand
SC Config "WdNisSvc_*" Start=Demand
SC Config "WinHttpAutoProxySvc" Start=Demand
SC Config "WinHttpAutoProxySvc_*" Start=Demand
SC Config "bthserv" Start=Demand
SC Config "bthserv_*" Start=Demand
SC Config "camsvc" Start=Demand
SC Config "camsvc_*" Start=Demand
SC Config "dcsvc" Start=Demand
SC Config "dcsvc_*" Start=Demand
SC Config "defragsvc" Start=Demand
SC Config "defragsvc_*" Start=Demand
SC Config "diagnosticshub.standardcollector.service" Start=Demand
SC Config "diagnosticshub.standardcollector.service_*" Start=Demand
SC Config "dot3svc" Start=Demand
SC Config "dot3svc_*" Start=Demand
SC Config "hidserv" Start=Demand
SC Config "hidserv_*" Start=Demand
SC Config "lmhosts" Start=Demand
SC Config "lmhosts_*" Start=Demand
SC Config "msiserver" Start=Demand
SC Config "msiserver_*" Start=Demand
SC Config "netprofm" Start=Demand
SC Config "netprofm_*" Start=Demand
SC Config "p2pimsvc" Start=Demand
SC Config "p2pimsvc_*" Start=Demand
SC Config "p2psvc" Start=Demand
SC Config "p2psvc_*" Start=Demand
SC Config "refsdedupsvc" Start=Demand
SC Config "refsdedupsvc_*" Start=Demand
SC Config "seclogon" Start=Demand
SC Config "seclogon_*" Start=Demand
SC Config "spectrum" Start=Demand
SC Config "spectrum_*" Start=Demand
SC Config "sppsvc" Start=Demand
SC Config "sppsvc_*" Start=Demand
SC Config "svsvc" Start=Demand
SC Config "svsvc_*" Start=Demand
SC Config "uhssvc" Start=Demand
SC Config "uhssvc_*" Start=Demand
SC Config "vds" Start=Demand
SC Config "vds_*" Start=Demand
SC Config "vm3dservice" Start=Demand
SC Config "vm3dservice_*" Start=Demand
SC Config "vmvss" Start=Demand
SC Config "vmvss_*" Start=Demand
SC Config "wmiApSrv" Start=Demand
SC Config "wmiApSrv_*" Start=Demand
SC Config "wuauserv" Start=Demand
SC Config "wuauser_*v" Start=Demand
SC Config "wudfsvc" Start=Demand
SC Config "wudfsvc_*" Start=Demand
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AppMgmt" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AppReadiness" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AppXSvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Appinfo" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\BITS" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\BTAGService" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\BluetoothUserService" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Browser" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\BthAvctpSvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\COMSysApp" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CaptureService" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ClipSVC" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DcpSvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DeviceAssociationService" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DeviceInstall" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DispBrokerDesktopSvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DisplayEnhancementService" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DsmSvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\EFS" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\EapHost" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\EventSystem" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\FontCache" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\FrameServer" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\FrameServerMonitor" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupListener" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupProvider" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\IEEtwCollectorService" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\InstallService" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\IpxlatCfgSvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\KeyIso" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\KtmRm" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\LicenseManager" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\LocalKdc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\LxpSvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MSDTC" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NPSMSvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NcbService" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NetSetupSvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Netman" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PNRPAutoREG" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PNRPsvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PcaSvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PerfHost" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PlugPlay" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PrintNotify" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\QWAVE" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RasMan" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RmSvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SharedRealitySvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ShellHWDetection" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SstpSvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\StorSvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TabletInputService" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Themes" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TimeBroker" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TokenBroker" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TrustedInstaller" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UI0Detect" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UdkUserSvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UsoSvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\VacSvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\VaultSvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\W32Time" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WSService" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WbioSrvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WcsPlugInService" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\bthserv" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\camsvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\dcsvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\defragsvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\dot3svc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\hidserv" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\lmhosts" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\msiserver" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\netprofm" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\p2pimsvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\p2psvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\refsdedupsvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\seclogon" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\spectrum" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\sppsvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\svsvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\uhssvc" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vds" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vm3dservice" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmvss" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wmiApSrv" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wuauserv" /V "Start" /T "REG_DWORD" /D "3" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wudfsvc" /V "Start" /T "REG_DWORD" /D "3" /F
echo.

ECHO Disabled services
SC Stop "AJRouter"
SC Stop "AJRouter_*"
SC Stop "ALG"
SC Stop "ALG_*"
SC Stop "AarSvc"
SC Stop "AarSvc_*"
SC Stop "AppIDSvc"
SC Stop "AppIDSvc_*"
SC Stop "AppVClient"
SC Stop "AppVClient_*"
SC Stop "ApxSvc"
SC Stop "ApxSvc_*"
SC Stop "AssignedAccessManagerSvc"
SC Stop "AssignedAccessManagerSvc_*"
SC Stop "AxInstSV"
SC Stop "AxInstSV_*"
SC Stop "BDESVC"
SC Stop "BDESVC_*"
SC Stop "BcastDVRUserService"
SC Stop "BcastDVRUserService_*"
SC Stop "CDPSvc"
SC Stop "CDPSvc_*"
SC Stop "CDPUserSvc"
SC Stop "CDPUserSvc_*"
SC Stop "CertPropSvc"
SC Stop "CertPropSvc_*"
SC Stop "CloudBackupRestoreSvc"
SC Stop "CloudBackupRestoreSvc_*"
SC Stop "ConsentUxUserSvc"
SC Stop "ConsentUxUserSvc_*"
SC Stop "CscService"
SC Stop "CscService_*"
SC Stop "DPS"
SC Stop "DPS_*"
SC Stop "DevQueryBroker"
SC Stop "DevQueryBroker_*"
SC Stop "DeviceAssociationBrokerSvc"
SC Stop "DeviceAssociationBrokerSvc_*"
SC Stop "DevicePickerUserSvc"
SC Stop "DevicePickerUserSvc_*"
SC Stop "DiagTrack"
SC Stop "DiagTrack_*"
SC Stop "DialogBlockingService"
SC Stop "DialogBlockingService_*"
SC Stop "DmEnrollmentSvc"
SC Stop "DmEnrollmentSvc_*"
SC Stop "DoSvc"
SC Stop "DoSvc_*"
SC Stop "DsSvc"
SC Stop "DsSvc_*"
SC Stop "DusmSvc"
SC Stop "DusmSvc_*"
SC Stop "EntAppSvc"
SC Stop "EntAppSvc_*"
SC Stop "FDResPub"
SC Stop "FDResPub_*"
SC Stop "Fax"
SC Stop "Fax_*"
SC Stop "GameInputSvc"
SC Stop "GameInputSvc_*"
SC Stop "HvHost"
SC Stop "HvHost_*"
SC Stop "IKEEXT"
SC Stop "IKEEXT_*"
SC Stop "InventorySvc"
SC Stop "InventorySvc_*"
SC Stop "MDCoreSvc"
SC Stop "MDCoreSvc_*"
SC Stop "MSiSCSI"
SC Stop "MSiSCSI_*"
SC Stop "MapsBroker"
SC Stop "MapsBroker_*"
SC Stop "McmSvc"
SC Stop "McmSvc_*"
SC Stop "McpManagementService"
SC Stop "McpManagementService_*"
SC Stop "MessagingService"
SC Stop "MessagingService_*"
SC Stop "MicrosoftEdgeElevationService"
SC Stop "MicrosoftEdgeElevationService_*"
SC Stop "MixedRealityOpenXRSvc"
SC Stop "MixedRealityOpenXRSvc_*"
SC Stop "MsKeyboardFilter"
SC Stop "MsKeyboardFilter_*"
SC Stop "NaturalAuthentication"
SC Stop "NaturalAuthentication_*"
SC Stop "NcaSvc"
SC Stop "NcaSvc_*"
SC Stop "NcdAutoSetup"
SC Stop "NcdAutoSetup_*"
SC Stop "NetTcpPortSharing"
SC Stop "NetTcpPortSharing_*"
SC Stop "Netlogon"
SC Stop "Netlogon_*"
SC Stop "NgcCtnrSvc"
SC Stop "NgcCtnrSvc_*"
SC Stop "NgcSvc"
SC Stop "NgcSvc_*"
SC Stop "OneSyncSvc"
SC Stop "OneSyncSvc_*"
SC Stop "P9RdrService"
SC Stop "P9RdrService_*"
SC Stop "PeerDistSvc"
SC Stop "PeerDistSvc_*"
SC Stop "PenService"
SC Stop "PenService_*"
SC Stop "PhoneSvc"
SC Stop "PhoneSvc_*"
SC Stop "PimIndexMaintenanceSvc"
SC Stop "PimIndexMaintenanceSvc_*"
SC Stop "PimIndexMaintenanceSvc_3b645"
SC Stop "PimIndexMaintenanceSvc_3b645_*"
SC Stop "PolicyAgent"
SC Stop "PolicyAgent_*"
SC Stop "PrintDeviceConfigurationService"
SC Stop "PrintDeviceConfigurationService_*"
SC Stop "PrintScanBrokerService"
SC Stop "PrintScanBrokerService_*"
SC Stop "PrintWorkflowUserSvc"
SC Stop "PrintWorkflowUserSvc_*"
SC Stop "PushToInstall"
SC Stop "PushToInstall_*"
SC Stop "RasAuto"
SC Stop "RasAuto_*"
SC Stop "RemoteAccess"
SC Stop "RemoteAccess_*"
SC Stop "RemoteREGistry"
SC Stop "RemoteREGistry_*"
SC Stop "RetailDemo"
SC Stop "RetailDemo_*"
SC Stop "RpcLocator"
SC Stop "RpcLocator_*"
SC Stop "SCPolicySvc"
SC Stop "SCPolicySvc_*"
SC Stop "SCardSvr"
SC Stop "SCardSvr_*"
SC Stop "SDRSVC"
SC Stop "SDRSVC_*"
SC Stop "SEMgrSvc"
SC Stop "SEMgrSvc_*"
SC Stop "SENS"
SC Stop "SENS_*"
SC Stop "SNMPTRAP"
SC Stop "SNMPTRAP_*"
SC Stop "SNMPTrap"
SC Stop "SNMPTrap_*"
SC Stop "SSDPSRV"
SC Stop "SSDPSRV_*"
SC Stop "ScDeviceEnum"
SC Stop "ScDeviceEnum_*"
SC Stop "SecurityHealthService"
SC Stop "SecurityHealthService_*"
SC Stop "Sense"
SC Stop "Sense_*"
SC Stop "SensorDataService"
SC Stop "SensorDataService_*"
SC Stop "SensorService"
SC Stop "SensorService_*"
SC Stop "SensrSvc"
SC Stop "SensrSvc_*"
SC Stop "SessionEnv"
SC Stop "SessionEnv_*"
SC Stop "SharedAccess"
SC Stop "SharedAccess_*"
SC Stop "SmsRouter"
SC Stop "SmsRouter_*"
SC Stop "Spooler"
SC Stop "Spooler_*"
SC Stop "StiSvc"
SC Stop "StiSvc_*"
SC Stop "SysMain"
SC Stop "SysMain_*"
SC Stop "TapiSrv"
SC Stop "TapiSrv_*"
SC Stop "TermService"
SC Stop "TermService_*"
SC Stop "TieringEngineService"
SC Stop "TieringEngineService_*"
SC Stop "TrkWks"
SC Stop "TrkWks_*"
SC Stop "TroubleshootingSvc"
SC Stop "TroubleshootingSvc_*"
SC Stop "UevAgentService"
SC Stop "UevAgentService_*"
SC Stop "UmRdpService"
SC Stop "UmRdpService_*"
SC Stop "UnistoreSvc"
SC Stop "UnistoreSvc_*"
SC Stop "UserDataSvc"
SC Stop "UserDataSvc_*"
SC Stop "VSS"
SC Stop "VSS_*"
SC Stop "WEPHOSTSVC"
SC Stop "WEPHOSTSVC_*"
SC Stop "WFDSConMgrSvc"
SC Stop "WFDSConMgrSvc_*"
SC Stop "WMPNetworkSvc"
SC Stop "WMPNetworkSvc_*"
SC Stop "WManSvc"
SC Stop "WManSvc_*"
SC Stop "WPDBusEnum"
SC Stop "WPDBusEnum_*"
SC Stop "WaaSMedicSvc"
SC Stop "WaaSMedicSvc_*"
SC Stop "WalletService"
SC Stop "WalletService_*"
SC Stop "WarpJITSvc"
SC Stop "WarpJITSvc_*"
SC Stop "WdiServiceHost"
SC Stop "WdiServiceHost_*"
SC Stop "WdiSystemHost"
SC Stop "WdiSystemHost_*"
SC Stop "WebClient"
SC Stop "WebClient_*"
SC Stop "Wecsvc"
SC Stop "Wecsvc_*"
SC Stop "WerSvc"
SC Stop "WerSvc"
SC Stop "WerSvc_*"
SC Stop "WiaRpc"
SC Stop "WiaRpc_*"
SC Stop "WinDefend"
SC Stop "WinDefend_*"
SC Stop "WinRM"
SC Stop "WinRM_*"
SC Stop "WpcMonSvc"
SC Stop "WpcMonSvc_*"
SC Stop "WpnService"
SC Stop "WpnService_*"
SC Stop "WwanSvc"
SC Stop "WwanSvc_*"
SC Stop "XblAuthManager"
SC Stop "XblAuthManager_*"
SC Stop "XblGameSave"
SC Stop "XblGameSave_*"
SC Stop "XboxGipSvc"
SC Stop "XboxGipSvc_*"
SC Stop "XboxNetApiSvc"
SC Stop "XboxNetApiSvc_*"
SC Stop "ZTHELPER"
SC Stop "ZTHELPER_*"
SC Stop "autotimesvc"
SC Stop "autotimesvc_*"
SC Stop "cbdhsvc"
SC Stop "cbdhsvc_*"
SC Stop "cloudidsvc"
SC Stop "cloudidsvc_*"
SC Stop "diagsvc"
SC Stop "diagsvc_*"
SC Stop "dmwappushservice"
SC Stop "dmwappushservice_*"
SC Stop "edgeupdate"
SC Stop "edgeupdate_*"
SC Stop "edgeupdatem"
SC Stop "edgeupdatem_*"
SC Stop "embeddedmode"
SC Stop "embeddedmode_*"
SC Stop "fdPHost"
SC Stop "fdPHost_*"
SC Stop "fhsvc"
SC Stop "fhsvc_*"
SC Stop "hpatchmon"
SC Stop "hpatchmon_*"
SC Stop "icssvc"
SC Stop "icssvc_*"
SC Stop "lfsvc"
SC Stop "lfsvc_*"
SC Stop "lltdsvc"
SC Stop "lltdsvc_*"
SC Stop "mpssvc"
SC Stop "mpssvc_*"
SC Stop "perceptionsimulation"
SC Stop "perceptionsimulation_*"
SC Stop "pla"
SC Stop "pla_*"
SC Stop "shpamsvc"
SC Stop "shpamsvc_*"
SC Stop "smphost"
SC Stop "smphost_*"
SC Stop "ssh-agent"
SC Stop "ssh-agent_*"
SC Stop "swprv"
SC Stop "swprv_*"
SC Stop "tzautoupdate"
SC Stop "tzautoupdate_*"
SC Stop "upnphost"
SC Stop "upnphost_*"
SC Stop "vmicguestinterface"
SC Stop "vmicguestinterface_*"
SC Stop "vmicheartbeat"
SC Stop "vmicheartbeat_*"
SC Stop "vmickvpexchange"
SC Stop "vmickvpexchange_*"
SC Stop "vmicrdv"
SC Stop "vmicrdv_*"
SC Stop "vmicshutdown"
SC Stop "vmicshutdown_*"
SC Stop "vmictimesync"
SC Stop "vmictimesync_*"
SC Stop "vmicvmsession"
SC Stop "vmicvmsession_*"
SC Stop "vmicvss"
SC Stop "vmicvss_*"
SC Stop "wbengine"
SC Stop "wbengine_*"
SC Stop "wcncsvc"
SC Stop "wcncsvc_*"
SC Stop "webthreatdefsvc"
SC Stop "webthreatdefusersvc"
SC Stop "wercplsupport"
SC Stop "wercplsupport_*"
SC Stop "whesvc"
SC Stop "whesvc_*"
SC Stop "wisvc"
SC Stop "wisvc_*"
SC Stop "wlidsvc"
SC Stop "wlidsvc_*"
SC Stop "wlpasvc"
SC Stop "wlpasvc_*"
SC Stop "workfolderssvc"
SC Stop "workfolderssvc_*"
SC Stop "wscsvc"
SC Stop "wscsvc_*"
SC Stop "wsearch"
SC Stop "wsearch_*"
SC Config "AJRouter" Start=Disabled
SC Config "AJRouter_*" Start=Disabled
SC Config "ALG" Start=Disabled
SC Config "ALG_*" Start=Disabled
SC Config "AarSvc" Start=Disabled
SC Config "AarSvc_*" Start=Disabled
SC Config "AppIDSvc" Start=Disabled
SC Config "AppIDSvc_*" Start=Disabled
SC Config "AppVClient" Start=Disabled
SC Config "AppVClient_*" Start=Disabled
SC Config "ApxSvc" Start=Disabled
SC Config "ApxSvc_*" Start=Disabled
SC Config "AssignedAccessManagerSvc" Start=Disabled
SC Config "AssignedAccessManagerSvc_*" Start=Disabled
SC Config "AxInstSV" Start=Disabled
SC Config "AxInstSV_*" Start=Disabled
SC Config "BDESVC" Start=Disabled
SC Config "BDESVC_*" Start=Disabled
SC Config "BcastDVRUserService" Start=Disabled
SC Config "BcastDVRUserService_*" Start=Disabled
SC Config "CDPSvc" Start=Disabled
SC Config "CDPSvc_*" Start=Disabled
SC Config "CDPUserSvc" Start=Disabled
SC Config "CDPUserSvc_*" Start=Disabled
SC Config "CertPropSvc" Start=Disabled
SC Config "CertPropSvc_*" Start=Disabled
SC Config "CloudBackupRestoreSvc" Start=Disabled
SC Config "CloudBackupRestoreSvc_*" Start=Disabled
SC Config "ConsentUxUserSvc" Start=Disabled
SC Config "ConsentUxUserSvc_*" Start=Disabled
SC Config "CscService" Start=Disabled
SC Config "CscService_*" Start=Disabled
SC Config "DPS" Start=Disabled
SC Config "DPS_*" Start=Disabled
SC Config "DevQueryBroker" Start=Disabled
SC Config "DevQueryBroker_*" Start=Disabled
SC Config "DeviceAssociationBrokerSvc" Start=Disabled
SC Config "DeviceAssociationBrokerSvc_*" Start=Disabled
SC Config "DevicePickerUserSvc" Start=Disabled
SC Config "DevicePickerUserSvc_*" Start=Disabled
SC Config "DiagTrack" Start=Disabled
SC Config "DiagTrack_*" Start=Disabled
SC Config "DialogBlockingService" Start=Disabled
SC Config "DialogBlockingService_*" Start=Disabled
SC Config "DmEnrollmentSvc" Start=Disabled
SC Config "DmEnrollmentSvc_*" Start=Disabled
SC Config "DoSvc" Start=Disabled
SC Config "DoSvc_*" Start=Disabled
SC Config "DsSvc" Start=Disabled
SC Config "DsSvc_*" Start=Disabled
SC Config "DusmSvc" Start=Disabled
SC Config "DusmSvc_*" Start=Disabled
SC Config "EntAppSvc" Start=Disabled
SC Config "EntAppSvc_*" Start=Disabled
SC Config "FDResPub" Start=Disabled
SC Config "FDResPub_*" Start=Disabled
SC Config "Fax" Start=Disabled
SC Config "Fax_*" Start=Disabled
SC Config "GameInputSvc" Start=Disabled
SC Config "GameInputSvc_*" Start=Disabled
SC Config "HvHost" Start=Disabled
SC Config "HvHost_*" Start=Disabled
SC Config "IKEEXT" Start=Disabled
SC Config "IKEEXT_*" Start=Disabled
SC Config "InventorySvc" Start=Disabled
SC Config "InventorySvc_*" Start=Disabled
SC Config "MDCoreSvc" Start=Disabled
SC Config "MDCoreSvc_*" Start=Disabled
SC Config "MSiSCSI" Start=Disabled
SC Config "MSiSCSI_*" Start=Disabled
SC Config "MapsBroker" Start=Disabled
SC Config "MapsBroker_*" Start=Disabled
SC Config "McmSvc" Start=Disabled
SC Config "McmSvc_*" Start=Disabled
SC Config "McpManagementService" Start=Disabled
SC Config "McpManagementService_*" Start=Disabled
SC Config "MessagingService" Start=Disabled
SC Config "MessagingService_*" Start=Disabled
SC Config "MicrosoftEdgeElevationService" Start=Disabled
SC Config "MicrosoftEdgeElevationService_*" Start=Disabled
SC Config "MixedRealityOpenXRSvc" Start=Disabled
SC Config "MixedRealityOpenXRSvc_*" Start=Disabled
SC Config "MsKeyboardFilter" Start=Disabled
SC Config "MsKeyboardFilter_*" Start=Disabled
SC Config "NaturalAuthentication" Start=Disabled
SC Config "NaturalAuthentication_*" Start=Disabled
SC Config "NcaSvc" Start=Disabled
SC Config "NcaSvc_*" Start=Disabled
SC Config "NcdAutoSetup" Start=Disabled
SC Config "NcdAutoSetup_*" Start=Disabled
SC Config "NetTcpPortSharing" Start=Disabled
SC Config "NetTcpPortSharing_*" Start=Disabled
SC Config "Netlogon" Start=Disabled
SC Config "Netlogon_*" Start=Disabled
SC Config "NgcCtnrSvc" Start=Disabled
SC Config "NgcCtnrSvc_*" Start=Disabled
SC Config "NgcSvc" Start=Disabled
SC Config "NgcSvc_*" Start=Disabled
SC Config "OneSyncSvc" Start=Disabled
SC Config "OneSyncSvc_*" Start=Disabled
SC Config "P9RdrService" Start=Disabled
SC Config "P9RdrService_*" Start=Disabled
SC Config "PeerDistSvc" Start=Disabled
SC Config "PeerDistSvc_*" Start=Disabled
SC Config "PenService" Start=Disabled
SC Config "PenService_*" Start=Disabled
SC Config "PhoneSvc" Start=Disabled
SC Config "PhoneSvc_*" Start=Disabled
SC Config "PimIndexMaintenanceSvc" Start=Disabled
SC Config "PimIndexMaintenanceSvc_*" Start=Disabled
SC Config "PimIndexMaintenanceSvc_3b645" Start=Disabled
SC Config "PimIndexMaintenanceSvc_3b645_*" Start=Disabled
SC Config "PolicyAgent" Start=Disabled
SC Config "PolicyAgent_*" Start=Disabled
SC Config "PrintDeviceConfigurationService" Start=Disabled
SC Config "PrintDeviceConfigurationService_*" Start=Disabled
SC Config "PrintScanBrokerService" Start=Disabled
SC Config "PrintScanBrokerService_*" Start=Disabled
SC Config "PrintWorkflowUserSvc" Start=Disabled
SC Config "PrintWorkflowUserSvc_*" Start=Disabled
SC Config "PushToInstall" Start=Disabled
SC Config "PushToInstall_*" Start=Disabled
SC Config "RasAuto" Start=Disabled
SC Config "RasAuto_*" Start=Disabled
SC Config "RemoteAccess" Start=Disabled
SC Config "RemoteAccess_*" Start=Disabled
SC Config "RemoteREGistry" Start=Disabled
SC Config "RemoteREGistry_*" Start=Disabled
SC Config "RetailDemo" Start=Disabled
SC Config "RetailDemo_*" Start=Disabled
SC Config "RpcLocator" Start=Disabled
SC Config "RpcLocator_*" Start=Disabled
SC Config "SCPolicySvc" Start=Disabled
SC Config "SCPolicySvc_*" Start=Disabled
SC Config "SCardSvr" Start=Disabled
SC Config "SCardSvr_*" Start=Disabled
SC Config "SDRSVC" Start=Disabled
SC Config "SDRSVC_*" Start=Disabled
SC Config "SEMgrSvc" Start=Disabled
SC Config "SEMgrSvc_*" Start=Disabled
SC Config "SENS" Start=Disabled
SC Config "SENS_*" Start=Disabled
SC Config "SNMPTRAP" Start=Disabled
SC Config "SNMPTRAP_*" Start=Disabled
SC Config "SNMPTrap" Start=Disabled
SC Config "SNMPTrap_*" Start=Disabled
SC Config "SSDPSRV" Start=Disabled
SC Config "SSDPSRV_*" Start=Disabled
SC Config "ScDeviceEnum" Start=Disabled
SC Config "ScDeviceEnum_*" Start=Disabled
SC Config "SecurityHealthService" Start=Disabled
SC Config "SecurityHealthService_*" Start=Disabled
SC Config "Sense" Start=Disabled
SC Config "Sense_*" Start=Disabled
SC Config "SensorDataService" Start=Disabled
SC Config "SensorDataService_*" Start=Disabled
SC Config "SensorService" Start=Disabled
SC Config "SensorService_*" Start=Disabled
SC Config "SensrSvc" Start=Disabled
SC Config "SensrSvc_*" Start=Disabled
SC Config "SessionEnv" Start=Disabled
SC Config "SessionEnv_*" Start=Disabled
SC Config "SharedAccess" Start=Disabled
SC Config "SharedAccess_*" Start=Disabled
SC Config "SmsRouter" Start=Disabled
SC Config "SmsRouter_*" Start=Disabled
SC Config "Spooler" Start=Disabled
SC Config "Spooler_*" Start=Disabled
SC Config "StiSvc" Start=Disabled
SC Config "StiSvc_*" Start=Disabled
SC Config "SysMain" Start=Disabled
SC Config "SysMain_*" Start=Disabled
SC Config "TapiSrv" Start=Disabled
SC Config "TapiSrv_*" Start=Disabled
SC Config "TermService" Start=Disabled
SC Config "TermService_*" Start=Disabled
SC Config "TieringEngineService" Start=Disabled
SC Config "TieringEngineService_*" Start=Disabled
SC Config "TrkWks" Start=Disabled
SC Config "TrkWks_*" Start=Disabled
SC Config "TroubleshootingSvc" Start=Disabled
SC Config "TroubleshootingSvc_*" Start=Disabled
SC Config "UevAgentService" Start=Disabled
SC Config "UevAgentService_*" Start=Disabled
SC Config "UmRdpService" Start=Disabled
SC Config "UmRdpService_*" Start=Disabled
SC Config "UnistoreSvc" Start=Disabled
SC Config "UnistoreSvc_*" Start=Disabled
SC Config "UserDataSvc" Start=Disabled
SC Config "UserDataSvc_*" Start=Disabled
SC Config "VSS" Start=Disabled
SC Config "VSS_*" Start=Disabled
SC Config "WEPHOSTSVC" Start=Disabled
SC Config "WEPHOSTSVC_*" Start=Disabled
SC Config "WFDSConMgrSvc" Start=Disabled
SC Config "WFDSConMgrSvc_*" Start=Disabled
SC Config "WMPNetworkSvc" Start=Disabled
SC Config "WMPNetworkSvc_*" Start=Disabled
SC Config "WManSvc" Start=Disabled
SC Config "WManSvc_*" Start=Disabled
SC Config "WPDBusEnum" Start=Disabled
SC Config "WPDBusEnum_*" Start=Disabled
SC Config "WaaSMedicSvc" Start=Disabled
SC Config "WaaSMedicSvc_*" Start=Disabled
SC Config "WalletService" Start=Disabled
SC Config "WalletService_*" Start=Disabled
SC Config "WarpJITSvc" Start=Disabled
SC Config "WarpJITSvc_*" Start=Disabled
SC Config "WdiServiceHost" Start=Disabled
SC Config "WdiServiceHost_*" Start=Disabled
SC Config "WdiSystemHost" Start=Disabled
SC Config "WdiSystemHost_*" Start=Disabled
SC Config "WebClient" Start=Disabled
SC Config "WebClient_*" Start=Disabled
SC Config "Wecsvc" Start=Disabled
SC Config "Wecsvc_*" Start=Disabled
SC Config "WerSvc" Start=Disabled
SC Config "WerSvc" Start=Disabled
SC Config "WerSvc_*" Start=Disabled
SC Config "WiaRpc" Start=Disabled
SC Config "WiaRpc_*" Start=Disabled
SC Config "WinDefend" Start=Disabled
SC Config "WinDefend_*" Start=Disabled
SC Config "WinRM" Start=Disabled
SC Config "WinRM_*" Start=Disabled
SC Config "WpcMonSvc" Start=Disabled
SC Config "WpcMonSvc_*" Start=Disabled
SC Config "WpnService" Start=Disabled
SC Config "WpnService_*" Start=Disabled
SC Config "WwanSvc" Start=Disabled
SC Config "WwanSvc_*" Start=Disabled
SC Config "XblAuthManager" Start=Disabled
SC Config "XblAuthManager_*" Start=Disabled
SC Config "XblGameSave" Start=Disabled
SC Config "XblGameSave_*" Start=Disabled
SC Config "XboxGipSvc" Start=Disabled
SC Config "XboxGipSvc_*" Start=Disabled
SC Config "XboxNetApiSvc" Start=Disabled
SC Config "XboxNetApiSvc_*" Start=Disabled
SC Config "ZTHELPER" Start=Disabled
SC Config "ZTHELPER_*" Start=Disabled
SC Config "autotimesvc" Start=Disabled
SC Config "autotimesvc_*" Start=Disabled
SC Config "cbdhsvc" Start=Disabled
SC Config "cbdhsvc_*" Start=Disabled
SC Config "cloudidsvc" Start=Disabled
SC Config "cloudidsvc_*" Start=Disabled
SC Config "diagsvc" Start=Disabled
SC Config "diagsvc_*" Start=Disabled
SC Config "dmwappushservice" Start=Disabled
SC Config "dmwappushservice_*" Start=Disabled
SC Config "edgeupdate" Start=Disabled
SC Config "edgeupdate_*" Start=Disabled
SC Config "edgeupdatem" Start=Disabled
SC Config "edgeupdatem_*" Start=Disabled
SC Config "embeddedmode" Start=Disabled
SC Config "embeddedmode_*" Start=Disabled
SC Config "fdPHost" Start=Disabled
SC Config "fdPHost_*" Start=Disabled
SC Config "fhsvc" Start=Disabled
SC Config "fhsvc_*" Start=Disabled
SC Config "hpatchmon" Start=Disabled
SC Config "hpatchmon_*" Start=Disabled
SC Config "icssvc" Start=Disabled
SC Config "icssvc_*" Start=Disabled
SC Config "lfsvc" Start=Disabled
SC Config "lfsvc_*" Start=Disabled
SC Config "lltdsvc" Start=Disabled
SC Config "lltdsvc_*" Start=Disabled
SC Config "mpssvc" Start=Disabled
SC Config "mpssvc_*" Start=Disabled
SC Config "perceptionsimulation" Start=Disabled
SC Config "perceptionsimulation_*" Start=Disabled
SC Config "pla" Start=Disabled
SC Config "pla_*" Start=Disabled
SC Config "shpamsvc" Start=Disabled
SC Config "shpamsvc_*" Start=Disabled
SC Config "smphost" Start=Disabled
SC Config "smphost_*" Start=Disabled
SC Config "ssh-agent" Start=Disabled
SC Config "ssh-agent_*" Start=Disabled
SC Config "swprv" Start=Disabled
SC Config "swprv_*" Start=Disabled
SC Config "tzautoupdate" Start=Disabled
SC Config "tzautoupdate_*" Start=Disabled
SC Config "upnphost" Start=Disabled
SC Config "upnphost_*" Start=Disabled
SC Config "vmicguestinterface" Start=Disabled
SC Config "vmicguestinterface_*" Start=Disabled
SC Config "vmicheartbeat" Start=Disabled
SC Config "vmicheartbeat_*" Start=Disabled
SC Config "vmickvpexchange" Start=Disabled
SC Config "vmickvpexchange_*" Start=Disabled
SC Config "vmicrdv" Start=Disabled
SC Config "vmicrdv_*" Start=Disabled
SC Config "vmicshutdown" Start=Disabled
SC Config "vmicshutdown_*" Start=Disabled
SC Config "vmictimesync" Start=Disabled
SC Config "vmictimesync_*" Start=Disabled
SC Config "vmicvmsession" Start=Disabled
SC Config "vmicvmsession_*" Start=Disabled
SC Config "vmicvss" Start=Disabled
SC Config "vmicvss_*" Start=Disabled
SC Config "wbengine" Start=Disabled
SC Config "wbengine_*" Start=Disabled
SC Config "wcncsvc" Start=Disabled
SC Config "wcncsvc_*" Start=Disabled
SC Config "webthreatdefsvc" Start=Disabled
SC Config "webthreatdefusersvc" Start=Disabled
SC Config "wercplsupport" Start=Disabled
SC Config "wercplsupport_*" Start=Disabled
SC Config "whesvc" Start=Disabled
SC Config "whesvc_*" Start=Disabled
SC Config "wisvc" Start=Disabled
SC Config "wisvc_*" Start=Disabled
SC Config "wlidsvc" Start=Disabled
SC Config "wlidsvc_*" Start=Disabled
SC Config "wlpasvc" Start=Disabled
SC Config "wlpasvc_*" Start=Disabled
SC Config "workfolderssvc" Start=Disabled
SC Config "workfolderssvc_*" Start=Disabled
SC Config "wscsvc" Start=Disabled
SC Config "wscsvc_*" Start=Disabled
SC Config "wsearch" Start=Disabled
SC Config "wsearch_*" Start=Disabled
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AJRouter" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ALG" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AarSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AppIDSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AppVClient" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ApxSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AssignedAccessManagerSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AxInstSV" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\BDESVC" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\BcastDVRUserService" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CDPSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CDPUserSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CertPropSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CloudBackupRestoreSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CscService" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DPS" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DevQueryBroker" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DialogBlockingService" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DmEnrollmentSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DoSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DsSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DusmSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\EntAppSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\FDResPub" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Fax" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\GameInputSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\HvHost" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\IKEEXT" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\InventorySvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MDCoreSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MSiSCSI" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MapsBroker" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\McmSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\McpManagementService" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MessagingService" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationService" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MixedRealityOpenXRSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MsKeyboardFilter" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NaturalAuthentication" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NcaSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NcdAutoSetup" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NgcCtnrSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NgcSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\OneSyncSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\P9RdrService" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PeerDistSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PenService" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PhoneSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc_3b645" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgent" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PrintDeviceConfigurationService" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PrintScanBrokerService" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PushToInstall" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RasAuto" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RemoteREGistry" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RetailDemo" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RpcLocator" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SCPolicySvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SCardSvr" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SDRSVC" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SEMgrSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SENS" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SNMPTRAP" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SNMPTrap" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SSDPSRV" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ScDeviceEnum" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SensorDataService" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SensorService" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SensrSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SessionEnv" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SmsRouter" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\StiSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SysMain" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TapiSrv" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TermService" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TieringEngineService" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TrkWks" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TroubleshootingSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UevAgentService" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UmRdpService" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UnistoreSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UserDataSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\VSS" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WEPHOSTSVC" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WFDSConMgrSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WManSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WPDBusEnum" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WalletService" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WarpJITSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WdiServiceHost" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WdiSystemHost" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WebClient" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Wecsvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WerSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WerSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WiaRpc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WinRM" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WpcMonSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WpnService" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WwanSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\XboxGipSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ZTHELPER" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\autotimesvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\cbdhsvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\cloudidsvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\diagsvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdate" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdatem" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\embeddedmode" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\fdPHost" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\fhsvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\hpatchmon" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\icssvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\lltdsvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\mpssvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\perceptionsimulation" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\pla" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\shpamsvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\smphost" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ssh-agent" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\swprv" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\tzautoupdate" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\upnphost" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmicguestinterface" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmicheartbeat" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmickvpexchange" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmicrdv" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmicshutdown" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmictimesync" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmicvmsession" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmicvss" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wbengine" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wcncsvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\webthreatdefsvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\webthreatdefusersvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wercplsupport" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\whesvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wisvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wlidsvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wlpasvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\workfolderssvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wscsvc" /V "Start" /T "REG_DWORD" /D "4" /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wsearch" /V "Start" /T "REG_DWORD" /D "4" /F


ECHO .
ECHO :::::::::::::::::::::::::::::::::::
ECHO ::::: Setting Scheduled Tasks :::::
ECHO :::::::::::::::::::::::::::::::::::
ECHO .

SchTasks /Change /TN "MicrosoftEdgeUpdateTaskMachineCore" /Disable
SchTasks /Change /TN "MicrosoftEdgeUpdateTaskMachineUA" /Disable
SchTasks /Change /TN "Microsoft\Office/OfficeTelemetryAgentFallBack" /Disable
SchTasks /Change /TN "Microsoft\Office/OfficeTelemetryAgentLogOn" /Disable
SchTasks /Change /TN "Microsoft\Windows\.NET Framework/.NET Framework NGEN v4.0.30319 64 Critical" /Disable
SchTasks /Change /TN "Microsoft\Windows\.NET Framework/.NET Framework NGEN v4.0.30319 Critical" /Disable
SchTasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical" /Disable
SchTasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64" /Disable
SchTasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical" /Disable
SchTasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319" /Disable
SchTasks /Change /TN "Microsoft\Windows\AccountHealth\RecoverabilityToastTask" /Disable
SchTasks /Change /TN "Microsoft\Windows\Application Experience/Microsoft Compatibility Appraiser Exp" /Disable
SchTasks /Change /TN "Microsoft\Windows\Application Experience/Microsoft Compatibility Appraiser" /Disable
SchTasks /Change /TN "Microsoft\Windows\Application Experience/StartupAppTask" /Disable
SchTasks /Change /TN "Microsoft\Windows\Application Experience\MareBackup" /Disable
SchTasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
SchTasks /Change /TN "Microsoft\Windows\Application Experience\PcaPatchDbTask" /Disable
SchTasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
SchTasks /Change /TN "Microsoft\Windows\Application Experience\SdbinstMergeDbTask" /Disable
SchTasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
SchTasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
SchTasks /Change /TN "Microsoft\Windows\BitLocker/BitLocker Encrypt All Drives" /Disable
SchTasks /Change /TN "Microsoft\Windows\BitLocker/BitLocker MDM policy Refresh" /Disable
SchTasks /Change /TN "Microsoft\Windows\BitLocker\BitLocker Encrypt All Drives" /Disable
SchTasks /Change /TN "Microsoft\Windows\BitLocker\BitLocker MDM policy Refresh" /Disable
SchTasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Disable
SchTasks /Change /TN "Microsoft\Windows\CloudRestore/Backup" /Disable
SchTasks /Change /TN "Microsoft\Windows\CloudRestore/Restore" /Disable
SchTasks /Change /TN "Microsoft\Windows\CloudRestore\Backup" /Disable
SchTasks /Change /TN "Microsoft\Windows\CloudRestore\Restore" /Disable
SchTasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program/Consolidator" /Disable
SchTasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
SchTasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
SchTasks /Change /TN "Microsoft\Windows\DUSM\dusmtask" /Disable
SchTasks /Change /TN "Microsoft\Windows\Device Information\Device User" /Disable
SchTasks /Change /TN "Microsoft\Windows\Device Information\Device" /Disable
SchTasks /Change /TN "Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" /Disable
SchTasks /Change /TN "Microsoft\Windows\Diagnosis\Scheduled" /Disable
SchTasks /Change /TN "Microsoft\Windows\Diagnosis\UnexpectedCodePath" /Disable
SchTasks /Change /TN "Microsoft\Windows\DiskCleanup\SilentCleanup" /Disable
SchTasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
SchTasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable
SchTasks /Change /TN "Microsoft\Windows\DiskFootprint\StorageSense" /Disable
SchTasks /Change /TN "Microsoft\Windows\EnterpriseMgmt\MDMMaintenenceTask" /Disable
SchTasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable
SchTasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /Disable
SchTasks /Change /TN "Microsoft\Windows\FileHistory/File History (maintenance mode)" /Disable
SchTasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable
SchTasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\ReconcileFeatures" /Disable
SchTasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataFlushing" /Disable
SchTasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataReporting" /Disable
SchTasks /Change /TN "Microsoft\Windows\Flighting\OneSettings\RefreshCache" /Disable
SchTasks /Change /TN "Microsoft\Windows\Input\LocalUserSyncDataAvailable" /Disable
SchTasks /Change /TN "Microsoft\Windows\Input\MouseSyncDataAvailable" /Disable
SchTasks /Change /TN "Microsoft\Windows\Input\PenSyncDataAvailable" /Disable
SchTasks /Change /TN "Microsoft\Windows\Input\TouchpadSyncDataAvailable" /Disable
SchTasks /Change /TN "Microsoft\Windows\Input\InputSettingsRestoreDataAvailable" /Disable
SchTasks /Change /TN "Microsoft\Windows\Input\RemoteMouseSyncDataAvailable" /Disable
SchTasks /Change /TN "Microsoft\Windows\Input\RemotePenSyncDataAvailable" /Disable
SchTasks /Change /TN "Microsoft\Windows\Input\RemoteTouchpadSyncDataAvailable" /Disable
SchTasks /Change /TN "Microsoft\Windows\International\Synchronize Language Settings" /Disable
SchTasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Installation" /Disable
SchTasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources" /Disable
SchTasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Uninstallation" /Disable
SchTasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /Disable
SchTasks /Change /TN "Microsoft\Windows\MUI\LPechoove" /Disable
SchTasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
SchTasks /Change /TN "Microsoft\Windows\Management\Provisioning\Cellular" /Disable
SchTasks /Change /TN "Microsoft\Windows\Management\Provisioning\Logon" /Disable
SchTasks /Change /TN "Microsoft\Windows\Maps\MapsToastTask" /Disable
SchTasks /Change /TN "Microsoft\Windows\Maps\MapsUpdateTask" /Disable
SchTasks /Change /TN "Microsoft\Windows\Multimedia\SystemSoundsService" /Disable
SchTasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
SchTasks /Change /TN "Microsoft\Windows\NlaSvc\WiFiTask" /Disable
SchTasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable
SchTasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Disable
SchTasks /Change /TN "Microsoft\Windows\Printing\EduPrintProv" /Disable
SchTasks /Change /TN "Microsoft\Windows\Printing\PrintJobCleanupTask" /Disable
SchTasks /Change /TN "Microsoft\Windows\Printing\PrinterCleanupTask" /Disable
SchTasks /Change /TN "Microsoft\Windows\PushToInstall\Registration" /Disable
SchTasks /Change /TN "Microsoft\Windows\Ras\MobilityManager" /Disable
SchTasks /Change /TN "Microsoft\Windows\RecoveryEnvironment\VerifyWinRE" /Disable
SchTasks /Change /TN "Microsoft\Windows\RetailDemo\CleanupOfflineContent" /Disable
SchTasks /Change /TN "Microsoft\Windows\Servicing\StartComponentCleanup" /Disable
SchTasks /Change /TN "Microsoft\Windows\SettingSync\NetworkStateChangeTask" /Disable
SchTasks /Change /TN "Microsoft\Windows\Setup\SetupCleanupTask" /Disable
SchTasks /Change /TN "Microsoft\Windows\Setup\SnapshotCleanupTask" /Disable
SchTasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable
SchTasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefreshTask" /Disable
SchTasks /Change /TN "Microsoft\Windows\Shell\ThemesSyncedImageDownload" /Disable
SchTasks /Change /TN "Microsoft\Windows\Shell\UpdateUserPictureTask" /Disable
SchTasks /Change /TN "Microsoft\Windows\SpacePort\SpaceAgentTask" /Disable
SchTasks /Change /TN "Microsoft\Windows\SpacePort\SpaceManagerTask" /Disable
SchTasks /Change /TN "Microsoft\Windows\Speech\SpeechModelDownloadTask" /Disable
SchTasks /Change /TN "Microsoft\Windows\Storage Tiers Management\Storage Tiers Management Initialization" /Disable
SchTasks /Change /TN "Microsoft\Windows\Sysmain\ResPriStaticDbSync" /Disable
SchTasks /Change /TN "Microsoft\Windows\Sysmain\WsSwapAssessmentTask" /Disable
SchTasks /Change /TN "Microsoft\Windows\SystemRestore\SR" /Disable
SchTasks /Change /TN "Microsoft\Windows\TPM\Tpm-HASCertRetr" /Disable
SchTasks /Change /TN "Microsoft\Windows\TPM\Tpm-Maintenance" /Disable
SchTasks /Change /TN "Microsoft\Windows\Task Manager\Interactive" /Disable
SchTasks /Change /TN "Microsoft\Windows\TextServicesFramework\MsCtfMonitor" /Disable
SchTasks /Change /TN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable
SchTasks /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable
SchTasks /Change /TN "Microsoft\Windows\Time Zone\SynchronizeTimeZone" /Disable
SchTasks /Change /TN "Microsoft\Windows\UPnP\UPnPHostConfig" /Disable
SchTasks /Change /TN "Microsoft\Windows\User Profile Service\HiveUploadTask" /Disable
SchTasks /Change /TN "Microsoft\Windows\WCM\WiFiTask" /Disable
SchTasks /Change /TN "Microsoft\Windows\WDI\ResolutionHost" /Disable
SchTasks /Change /TN "Microsoft\Windows\WOF\WIM-Hash-Management" /Disable
SchTasks /Change /TN "Microsoft\Windows\WOF\WIM-Hash-Validation" /Disable
SchTasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
SchTasks /Change /TN "Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" /Disable
SchTasks /Change /TN "Microsoft\Windows\WindowsAI\Settings\InitialConfiguration" /Disable
SchTasks /Change /TN "Microsoft\Windows\WlanSvc\CDSSync" /Disable
SchTasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Logon Synchronization" /Disable
SchTasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Maintenance Work" /Disable
SchTasks /Change /TN "Microsoft\Windows\Workplace Join\Automatic-Device-Join" /Disable
SchTasks /Change /TN "Microsoft\Windows\WwanSvc\NotificationTask" /Disable
SchTasks /Change /TN "Microsoft\Windows\WwanSvc\OobeDiscovery" /Disable
SchTasks /Change /TN "Microsoft\Windows\echooteAssistance\echooteAssistanceTask" /Disable
SchTasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /Disable


ECHO .
ECHO ::::::::::::::::::::::::::::::
ECHO ::::: Cleaning Edge Temp :::::
ECHO ::::::::::::::::::::::::::::::
ECHO .

DEL /S /Q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History*" >nul 2>&1
DEL /S /Q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Media History*" >nul 2>&1
DEL /S /Q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Visited Links*" >nul 2>&1
DEL /S /Q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Top Sites*" >nul 2>&1
DEL /S /Q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Network Action Predictor*" >nul 2>&1
DEL /S /Q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Shortcuts*" >nul 2>&1
DEL /S /Q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Network\Cookies*" >nul 2>&1
DEL /S /Q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Web Data*" >nul 2>&1
PushD "%LocalAppData%\Microsoft\Edge\User Data\Default\Session Storage" && (RD /S /Q "%LocalAppData%\Microsoft\Edge\User Data\Default\Session Storage" 2>nul & popd)
PushD "%LocalAppData%\Microsoft\Edge\User Data\Default\Sync Data" && (RD /S /Q "%LocalAppData%\Microsoft\Edge\User Data\Default\Sync Data" 2>nul & popd)
PushD "%LocalAppData%\Microsoft\Edge\User Data\Default\Telemetry" && (RD /S /Q "%LocalAppData%\Microsoft\Edge\User Data\Default\Telemetry" 2>nul & popd)
PushD "%LocalAppData%\Microsoft\Edge\User Data\CrashReports" && (RD /S /Q "%LocalAppData%\Microsoft\Edge\User Data\CrashReports" 2>nul & popd)
PushD "%LocalAppData%\Microsoft\EdgeUpdate\Log" && (RD /S /Q "%LocalAppData%\Microsoft\EdgeUpdate\Log" 2>nul & popd)
PushD "%LocalAppData%\Microsoft\EdgeUpdate\Download" && (RD /S /Q "%LocalAppData%\Microsoft\EdgeUpdate\Download" 2>nul & popd)
PushD "%LocalAppData%\Microsoft\EdgeUpdate\Install" && (RD /S /Q "%LocalAppData%\Microsoft\EdgeUpdate\Install" 2>nul & popd)
PushD "%LocalAppData%\Microsoft\EdgeUpdate\Offline" && (RD /S /Q "%LocalAppData%\Microsoft\EdgeUpdate\Offline" 2>nul & popd)
PushD "%LocalAppData%\Microsoft\Edge\User Data\BrowserMetrics" && (RD /S /Q "%LocalAppData%\Microsoft\Edge\User Data\BrowserMetrics" 2>nul & popd)
PushD "%LocalAppData%\Microsoft\Edge\User Data\Crashpad\reports" && (RD /S /Q "%LocalAppData%\Microsoft\Edge\User Data\Crashpad\reports" 2>nul & popd)
PushD "%LocalAppData%\Microsoft\Edge\User Data\Stability" && (RD /S /Q "%LocalAppData%\Microsoft\Edge\User Data\Stability" 2>nul & popd)
PushD "%LocalAppData%\Microsoft\Edge\User Data\Stability" && (RD /S /Q "%LocalAppData%\Microsoft\Edge\User Data\Stability" 2>nul & popd)
PushD "%LocalAppData%\Microsoft\Edge\User Data\Feature Engagement Tracker" && (RD /S /Q "%LocalAppData%\Microsoft\Edge\User Data\Feature Engagement Tracker" 2>nul & popd)


ECHO .
ECHO ::::::::::::::::::::::::::::::::
ECHO ::::: Cleaning Office Temp :::::
ECHO ::::::::::::::::::::::::::::::::
ECHO .

PushD "%LOCALAPPDATA%\Microsoft\Office\16.0\Wef\" && (RD /S /Q "%LOCALAPPDATA%\Microsoft\Office\16.0\Wef\" 2>nul & popd)
PushD "%userprofile%\AppData\Local\Packages\Microsoft.Win32WebViewHost_cw5n1h2txyewy\AC\#!123\INetCache\" && (RD /S /Q "%userprofile%\AppData\Local\Packages\Microsoft.Win32WebViewHost_cw5n1h2txyewy\AC\#!123\INetCache\" 2>nul & popd)
PushD "%userprofile%\AppData\Local\Microsoft\Outlook\HubAppFileCache" && (RD /S /Q "%userprofile%\AppData\Local\Microsoft\Outlook\HubAppFileCache" 2>nul & popd)


ECHO .
ECHO :::::::::::::::::::::::::::::::::
ECHO ::::: Cleaning Windows Temp :::::
ECHO :::::::::::::::::::::::::::::::::
ECHO .

TakeOwn /S %computername% /U %username% /F "%WinDir%\System32\smartscreen.exe"
icacls "%WinDir%\System32\smartscreen.exe" /grant:r %username%:f
TaskKill /IM "smartscreen.exe" /F
DEL "%WinDir%\System32\smartscreen.exe" /S /F /Q
TaskKill /F /IM "CrossDeviceResume.exe" >nul 2>&1
CD "%WINDIR%\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy" >nul 2>&1
TakeOwn /F "Microsoft.Web.WebView2.Core.dll" >nul 2>&1
icacls "Microsoft.Web.WebView2.Core.dll" /grant administrators:f >nul 2>&1
DEL /F /Q "%WINDIR%\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\Microsoft.Web.WebView2.Core.dll" >nul 2>&1
CD /D "%WINDIR%\System32" >nul 2>&1
rundll32.exe pnpclean.dll,RunDLL_PnpClean /drivers /maxclean >nul 2>&1
CleanMgr /Sagerun 1 >nul 2>&1
CleanMgr /VeryLowDisk >nul 2>&1
RD /S /Q "%SystemDrive%\$GetCurrent" >nul 2>&1
RD /S /Q "%SystemDrive%\$SysReset" >nul 2>&1
RD /S /Q "%SystemDrive%\$Windows.~BT" >nul 2>&1
RD /S /Q "%SystemDrive%\$Windows.~WS" >nul 2>&1
RD /S /Q "%SystemDrive%\$WinREAgent" >nul 2>&1
RD /S /Q "%SystemDrive%\OneDriveTemp" >nul 2>&1
RD /S /Q "%SystemDrive%\Windows.old" >nul 2>&1
PushD "%SystemDrive%\Recovery" && (RD /S /Q "%SystemDrive%\Recovery" 2>nul & popd)
%WINDIR%\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 1 >nul 2>&1
%WINDIR%\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 2 >nul 2>&1
%WINDIR%\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 4 >nul 2>&1
%WINDIR%\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 8 >nul 2>&1
%WINDIR%\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 10 >nul 2>&1
%WINDIR%\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 16 >nul 2>&1
%WINDIR%\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 20 >nul 2>&1
%WINDIR%\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 32 >nul 2>&1
%WINDIR%\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 64 >nul 2>&1
%WINDIR%\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 40 >nul 2>&1
%WINDIR%\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 80 >nul 2>&1
%WINDIR%\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 128 >nul 2>&1
%WINDIR%\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 255 >nul 2>&1
%WINDIR%\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 800 >nul 2>&1
%WINDIR%\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 4351 >nul 2>&1
PushD "%ProgramData%\USOShared\Logs" && (RD /S /Q "%ProgramData%\USOShared\Logs" 2>nul & popd)
PushD "%LocalAppData%\Microsoft\Windows\WER" && (RD /S /Q "%LocalAppData%\Microsoft\Windows\WER" 2>nul & popd)
PushD "%LocalAppData%\Microsoft\Windows\INetCache" && (RD /S /Q "%LocalAppData%\Microsoft\Windows\INetCache" 2>nul & popd)
PushD "%LocalAppData%\Microsoft\Windows\INetCookies" && (RD /S /Q "%LocalAppData%\Microsoft\Windows\INetCookies" 2>nul & popd)
PushD "%LocalAppData%\Microsoft\Windows\IECompatCache" && (RD /S /Q "%LocalAppData%\Microsoft\Windows\IECompatCache" 2>nul & popd)
PushD "%LocalAppData%\Microsoft\Windows\IECompatUaCache" && (RD /S /Q "%LocalAppData%\Microsoft\Windows\IECompatUaCache" 2>nul & popd)
PushD "%LocalAppData%\Microsoft\Windows\IEDownloadHistory" && (RD /S /Q "%LocalAppData%\Microsoft\Windows\IEDownloadHistory" 2>nul & popd)
PushD "%LocalAppData%\Microsoft\Windows\Temporary Internet Files" && (RD /S /Q "%LocalAppData%\Microsoft\Windows\Temporary Internet Files" 2>nul & popd)
PushD "%LocalAppData%\Microsoft\Windows\WebCache" && (RD /S /Q "%LocalAppData%\Microsoft\Windows\WebCache" 2>nul & popd)
PushD "%WINDIR%\Prefetch" && (RD /S /Q "%WINDIR%\Prefetch" 2>nul & popd)
PushD "%WINDIR%\SoftwareDistribution\Download" && (RD /S /Q "%WINDIR%\SoftwareDistribution\Download" 2>nul & popd)
PushD "%SystemDrive%\$Recycle.Bin" && (RD /S /Q "%SystemDrive%\$Recycle.Bin" 2>nul & popd)
PushD "%WINDIR%\System32\winevt\Logs" && (RD /S /Q "%WINDIR%\System32\winevt\Logs" 2>nul & popd)
PushD "%WINDIR%\Logs" && (RD /S /Q "%WINDIR%\Logs" 2>nul & popd)
PushD "%temp%" && (RD /S /Q "%temp%" 2>nul & popd)
PushD "%SystemDrive%\Temp\" && (RD /S /Q "%SystemDrive%\Temp\" 2>nul & popd)
PushD "%LOCALAPPDATA%\Temp" && (RD /S /Q "%LOCALAPPDATA%\Temp" 2>nul & popd)
PushD "%WINDIR%\Temp" && (RD /S /Q "%WINDIR%\Temp" 2>nul & popd)


ECHO .
ECHO :::::::::::::::::::::::::::::
ECHO ::::: Disk Optimization :::::
ECHO :::::::::::::::::::::::::::::
ECHO .

Defrag C: /O


ECHO :: Optimization completed successfully. :: Script by S.H.E.I.K.H


ECHO .
ECHO :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO :::: Warning! Press any key to shutdown or simply close this batch file. ::::
ECHO :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

Pause

RD /S /Q "%SystemDrive%\$GetCurrent" >nul 2>&1
RD /S /Q "%SystemDrive%\$SysReset" >nul 2>&1
RD /S /Q "%SystemDrive%\$Windows.~BT" >nul 2>&1
RD /S /Q "%SystemDrive%\$Windows.~WS" >nul 2>&1
RD /S /Q "%SystemDrive%\$WinREAgent" >nul 2>&1
RD /S /Q "%SystemDrive%\OneDriveTemp" >nul 2>&1
RD /S /Q "%SystemDrive%\Windows.old" >nul 2>&1
PushD "%SystemDrive%\Recovery" && (RD /S /Q "%SystemDrive%\Recovery" 2>nul & popd)
PushD "%ProgramData%\USOShared\Logs" && (RD /S /Q "%ProgramData%\USOShared\Logs" 2>nul & popd)
PushD "%LocalAppData%\Microsoft\Windows\WER" && (RD /S /Q "%LocalAppData%\Microsoft\Windows\WER" 2>nul & popd)
PushD "%LocalAppData%\Microsoft\Windows\INetCache" && (RD /S /Q "%LocalAppData%\Microsoft\Windows\INetCache" 2>nul & popd)
PushD "%LocalAppData%\Microsoft\Windows\INetCookies" && (RD /S /Q "%LocalAppData%\Microsoft\Windows\INetCookies" 2>nul & popd)
PushD "%LocalAppData%\Microsoft\Windows\IECompatCache" && (RD /S /Q "%LocalAppData%\Microsoft\Windows\IECompatCache" 2>nul & popd)
PushD "%LocalAppData%\Microsoft\Windows\IECompatUaCache" && (RD /S /Q "%LocalAppData%\Microsoft\Windows\IECompatUaCache" 2>nul & popd)
PushD "%LocalAppData%\Microsoft\Windows\IEDownloadHistory" && (RD /S /Q "%LocalAppData%\Microsoft\Windows\IEDownloadHistory" 2>nul & popd)
PushD "%LocalAppData%\Microsoft\Windows\Temporary Internet Files" && (RD /S /Q "%LocalAppData%\Microsoft\Windows\Temporary Internet Files" 2>nul & popd)
PushD "%LocalAppData%\Microsoft\Windows\WebCache" && (RD /S /Q "%LocalAppData%\Microsoft\Windows\WebCache" 2>nul & popd)
PushD "%WINDIR%\Prefetch" && (RD /S /Q "%WINDIR%\Prefetch" 2>nul & popd)
PushD "%WINDIR%\SoftwareDistribution\Download" && (RD /S /Q "%WINDIR%\SoftwareDistribution\Download" 2>nul & popd)
PushD "%SystemDrive%\$Recycle.Bin" && (RD /S /Q "%SystemDrive%\$Recycle.Bin" 2>nul & popd)
PushD "%WINDIR%\System32\winevt\Logs" && (RD /S /Q "%WINDIR%\System32\winevt\Logs" 2>nul & popd)
PushD "%WINDIR%\Logs" && (RD /S /Q "%WINDIR%\Logs" 2>nul & popd)
PushD "%temp%" && (RD /S /Q "%temp%" 2>nul & popd)
PushD "%SystemDrive%\Temp\" && (RD /S /Q "%SystemDrive%\Temp\" 2>nul & popd)
PushD "%LOCALAPPDATA%\Temp" && (RD /S /Q "%LOCALAPPDATA%\Temp" 2>nul & popd)
PushD "%WINDIR%\Temp" && (RD /S /Q "%WINDIR%\Temp" 2>nul & popd)
Shutdown /S /T 0
