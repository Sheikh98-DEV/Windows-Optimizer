@ECHO OFF
SETLOCAL EnableDelayedExpansion
SET version=5.0.0
Set ReleaseTime=Jul 18, 2025
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
ECHO ::     Windows Optimizer Script      ::
ECHO ::                                   ::
ECHO ::      Version %version% (Stable)       ::
ECHO ::                                   ::
ECHO ::   %ReleaseTime% by  S.H.E.I.K.H    ::
ECHO ::                                   ::
ECHO ::       GitHub: Sheikh98-DEV        ::
ECHO :::::::::::::::::::::::::::::::::::::::
ECHO .
ECHO For Post-install use only.
ECHO Recommended to re-launch after Windows updates.
ECHO .
ECHO Press any key to start optimization ...
Pause >null


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

REG Query "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /V "CrashDumpEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /V "CrashDumpEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /V "RPSessionInterval"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /V "RPSessionInterval" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /V "EnableActivityFeed"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /V "EnableActivityFeed" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /V "PublishUserActivities"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /V "PublishUserActivities" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /V "UploadUserActivities"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /V "UploadUserActivities" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /V "Value"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /V "Value" /T "REG_SZ" /D "Deny" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /V "SensorPermissionState"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /V "SensorPermissionState" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /V "Status"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /V "Status" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SYSTEM\Maps" /V "AutoUpdateEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\Maps" /V "AutoUpdateEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "ContentDeliveryAllowed"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "ContentDeliveryAllowed" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEverEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEverEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338387Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338387Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338387Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338387Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338388Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338388Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManage" /V "SubscribedContent-338389Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338389Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353698Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353698Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SystemPaneSuggestionsEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SystemPaneSuggestionsEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Siuf\Rules" /V "NumberOfSIUFInPeriod"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Siuf\Rules" /V "NumberOfSIUFInPeriod" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "NumberOfSIUFInPeriod"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "NumberOfSIUFInPeriod" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /V "DoNotShowFeedbackNotifications"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /V "DoNotShowFeedbackNotifications" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V "DisableTailoredExperiencesWithDiagnosticData"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V "DisableTailoredExperiencesWithDiagnosticData" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /V "DisabledByGroupPolicy"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /V "DisabledByGroupPolicy" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /V "DODownloadMode"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /V "DODownloadMode" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Control\remote Assistance" /V "fAllowToGetHelp"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Control\remote Assistance" /V "fAllowToGetHelp" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /V "SearchOrderConfig"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /V "SearchOrderConfig" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /V "SystemResponsiveness"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /V "SystemResponsiveness" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /V "NetworkThrottlingIndex"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /V "NetworkThrottlingIndex" /T "REG_DWORD" /D "4294967295" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /V "ClearPageFileAtShutdown"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /V "ClearPageFileAtShutdown" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /V "IRPStackSize"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /V "IRPStackSize" /T "REG_DWORD" /D "30" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V "HideSCAMeetNow"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V "HideSCAMeetNow" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /V "ScoobeSystemSettingEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /V "ScoobeSystemSettingEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /V "Value"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /V "Value" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /V "Value"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /V "Value" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" /V "TurnOffWindowsCopilot"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" /V "TurnOffWindowsCopilot" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\Software\Policies\Microsoft\Windows\WindowsCopilot" /V "TurnOffWindowsCopilot"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Policies\Microsoft\Windows\WindowsCopilot" /V "TurnOffWindowsCopilot" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /V "DisableAIDataAnalysis"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /V "DisableAIDataAnalysis" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /V "DisableWpbtExecution"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /V "DisableWpbtExecution" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\System\GameConfigStore" /V "GameDVR_FSEBehavior"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\System\GameConfigStore" /V "GameDVR_FSEBehavior" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\System\GameConfigStore" /V "GameDVR_Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\System\GameConfigStore" /V "GameDVR_Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\System\GameConfigStore" /V "GameDVR_HonorUserFSEBehaviorMode"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\System\GameConfigStore" /V "GameDVR_HonorUserFSEBehaviorMode" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\System\GameConfigStore" /V "GameDVR_EFSEFeatureFlags"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\System\GameConfigStore" /V "GameDVR_EFSEFeatureFlags" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /V "GlobalUserDisabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /V "GlobalUserDisabled" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Education" /V "IsEducationEnvironment"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Education" /V "IsEducationEnvironment" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SYSTEM\CurrentControlSet\Control\CrashControl" /V "CrashDumpEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SYSTEM\CurrentControlSet\Control\CrashControl" /V "CrashDumpEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /V "RPSessionInterval"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /V "RPSessionInterval" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\System" /V "EnableActivityFeed"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\System" /V "EnableActivityFeed" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\System" /V "PublishUserActivities"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\System" /V "PublishUserActivities" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\System" /V "UploadUserActivities"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\System" /V "UploadUserActivities" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /V "Value"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /V "Value" /T "REG_SZ" /D "Deny" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /V "SensorPermissionState"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /V "SensorPermissionState" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /V "Status"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /V "Status" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SYSTEM\Maps" /V "AutoUpdateEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SYSTEM\Maps" /V "AutoUpdateEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "ContentDeliveryAllowed"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "ContentDeliveryAllowed" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEverEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEverEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338387Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338387Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338387Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338387Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338388Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338388Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManage" /V "SubscribedContent-338389Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338389Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353698Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353698Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SystemPaneSuggestionsEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SystemPaneSuggestionsEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /V "NumberOfSIUFInPeriod"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /V "NumberOfSIUFInPeriod" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "NumberOfSIUFInPeriod"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "NumberOfSIUFInPeriod" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /V "DoNotShowFeedbackNotifications"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /V "DoNotShowFeedbackNotifications" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V "DisableTailoredExperiencesWithDiagnosticData"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V "DisableTailoredExperiencesWithDiagnosticData" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /V "DisabledByGroupPolicy"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /V "DisabledByGroupPolicy" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /V "DODownloadMode"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /V "DODownloadMode" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SYSTEM\CurrentControlSet\Control\remote Assistance" /V "fAllowToGetHelp"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SYSTEM\CurrentControlSet\Control\remote Assistance" /V "fAllowToGetHelp" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /V "EnthusiastMode"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /V "EnthusiastMode" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "LaunchTo"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "LaunchTo" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /V "SearchOrderConfig"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /V "SearchOrderConfig" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /V "SystemResponsiveness"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /V "SystemResponsiveness" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /V "NetworkThrottlingIndex"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /V "NetworkThrottlingIndex" /T "REG_DWORD" /D "4294967295" /F
)

REG Query "HKCU\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /V "ClearPageFileAtShutdown"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /V "ClearPageFileAtShutdown" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /V "IRPStackSize"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /V "IRPStackSize" /T "REG_DWORD" /D "30" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V "HideSCAMeetNow"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V "HideSCAMeetNow" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /V "ScoobeSystemSettingEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /V "ScoobeSystemSettingEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /V "Value"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /V "Value" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /V "Value"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /V "Value" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" /V "TurnOffWindowsCopilot"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" /V "TurnOffWindowsCopilot" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot" /V "TurnOffWindowsCopilot"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot" /V "TurnOffWindowsCopilot" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /V "DisableAIDataAnalysis"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /V "DisableAIDataAnalysis" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SYSTEM\CurrentControlSet\Control\Session Manager" /V "DisableWpbtExecution"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SYSTEM\CurrentControlSet\Control\Session Manager" /V "DisableWpbtExecution" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\System\GameConfigStore" /V "GameDVR_FSEBehavior"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\System\GameConfigStore" /V "GameDVR_FSEBehavior" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\System\GameConfigStore" /V "GameDVR_Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\System\GameConfigStore" /V "GameDVR_Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\System\GameConfigStore" /V "GameDVR_HonorUserFSEBehaviorMode"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\System\GameConfigStore" /V "GameDVR_HonorUserFSEBehaviorMode" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\System\GameConfigStore" /V "GameDVR_EFSEFeatureFlags"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\System\GameConfigStore" /V "GameDVR_EFSEFeatureFlags" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /V "GlobalUserDisabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /V "GlobalUserDisabled" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\PolicyManager\current\device\Education" /V "IsEducationEnvironment"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\PolicyManager\current\device\Education" /V "IsEducationEnvironment" /T "REG_DWORD" /D "0" /F
)


ECHO .
ECHO ::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Microsoft Defender :::::
ECHO ::::::::::::::::::::::::::::::::::::::::
echo.

::::::::::::::::::::::::::::::::
ECHO Disabling Tamper Protection
::::::::::::::::::::::::::::::::

REG Query "HKLM\Software\Microsoft\Windows Defender\Features" /V "TamperProtection"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows Defender\Features" /V "TamperProtection" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows Defender\Features" /V "TamperProtection"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows Defender\Features" /V "TamperProtection" /T "REG_DWORD" /D "0" /F
)

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling System GuaRD Runtime Monitor Broker (when disabled, it might cause BSOD Critical Process Died)
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

REG Query "HKLM\System\CurrentControlSet\Services\SgrmBroker" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\System\CurrentControlSet\Services\SgrmBroker" /V "Start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKCU\System\CurrentControlSet\Services\SgrmBroker" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\System\CurrentControlSet\Services\SgrmBroker" /V "Start" /T "REG_DWORD" /D "4" /F
)

:::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling Windows Defender Security Center
:::::::::::::::::::::::::::::::::::::::::::::::

REG Query "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /V "Start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKCU\System\CurrentControlSet\Services\SecurityHealthService" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\System\CurrentControlSet\Services\SecurityHealthService" /V "Start" /T "REG_DWORD" /D "4" /F
)

::::::::::::::::::::::::::::::::::::::
ECHO Disabling Antivirus Notifications
::::::::::::::::::::::::::::::::::::::

REG Query "HKLM\Software\Microsoft\Windows Defender Security Center\Notifications" /V "DisableNotifications"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows Defender Security Center\Notifications" /V "DisableNotifications" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Notifications" /V "DisableEnhancedNotifications"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Notifications" /V "DisableEnhancedNotifications" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Microsoft\Windows Defender Security Center\Notifications" /V "DisableNotifications"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows Defender Security Center\Notifications" /V "DisableNotifications" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Policies\Microsoft\Windows Defender Security Center\Notifications" /V "DisableEnhancedNotifications"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender Security Center\Notifications" /V "DisableEnhancedNotifications" /T "REG_DWORD" /D "1" /F
)

:::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling Security and Maitenance Notification
:::::::::::::::::::::::::::::::::::::::::::::::::::

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

:::::::::::::::::::::::::::::::::::
ECHO Disabling Real-time protection
:::::::::::::::::::::::::::::::::::

REG Query "HKLM\Software\Policies\Microsoft\Windows Defender" /V "AllowFastServiceStartup"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender" /V "AllowFastServiceStartup" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Policies\Microsoft\Windows Defender" /V "DisableAntiSpyware"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender" /V "DisableAntiSpyware" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\Software\Policies\Microsoft\Windows Defender" /V "DisableAntiVirus"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender" /V "DisableAntiVirus" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\Software\Policies\Microsoft\Windows Defender" /V "DisableSpecialRunningModes"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender" /V "DisableSpecialRunningModes" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\Software\Policies\Microsoft\Windows Defender" /V "ServiceKeepAlive"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender" /V "ServiceKeepAlive" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /V "MpEnablePus"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /V "MpEnablePus" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableBehaviorMonitoring"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableBehaviorMonitoring" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableIOAVProtection"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableIOAVProtection" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableOnAccessProtection"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableOnAccessProtection" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableRealtimeMonitoring"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableRealtimeMonitoring" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableRoutinelyTakingAction"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableRoutinelyTakingAction" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableScanOnRealtimeEnable"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableScanOnRealtimeEnable" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /V "DisableEnhancedNotifications"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /V "DisableEnhancedNotifications" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /V "DisableBlockAtFirstSeen"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /V "DisableBlockAtFirstSeen" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /V "SpynetReporting"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /V "SpynetReporting" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /V "SubmitSamplesConsent"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /V "SubmitSamplesConsent" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\Software\Policies\Microsoft\Windows Defender" /V "AllowFastServiceStartup"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender" /V "AllowFastServiceStartup" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Policies\Microsoft\Windows Defender" /V "DisableAntiSpyware"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender" /V "DisableAntiSpyware" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Policies\Microsoft\Windows Defender" /V "DisableAntiVirus"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender" /V "DisableAntiVirus" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Policies\Microsoft\Windows Defender" /V "DisableSpecialRunningModes"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender" /V "DisableSpecialRunningModes" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Policies\Microsoft\Windows Defender" /V "ServiceKeepAlive"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender" /V "ServiceKeepAlive" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Policies\Microsoft\Windows Defender\MpEngine" /V "MpEnablePus"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\MpEngine" /V "MpEnablePus" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableBehaviorMonitoring"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableBehaviorMonitoring" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableIOAVProtection"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableIOAVProtection" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableOnAccessProtection"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableOnAccessProtection" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableRealtimeMonitoring"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableRealtimeMonitoring" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableRoutinelyTakingAction"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableRoutinelyTakingAction" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableScanOnRealtimeEnable"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableScanOnRealtimeEnable" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Policies\Microsoft\Windows Defender\Reporting" /V "DisableEnhancedNotifications"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\Reporting" /V "DisableEnhancedNotifications" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Policies\Microsoft\Windows Defender\SpyNet" /V "DisableBlockAtFirstSeen"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\SpyNet" /V "DisableBlockAtFirstSeen" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Policies\Microsoft\Windows Defender\SpyNet" /V "SpynetReporting"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\SpyNet" /V "SpynetReporting" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Policies\Microsoft\Windows Defender\SpyNet" /V "SubmitSamplesConsent"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\SpyNet" /V "SubmitSamplesConsent" /T "REG_DWORD" /D "2" /F
)

::::::::::::::::::::::
ECHO Disabling Logging
::::::::::::::::::::::

REG Query "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /V "Start" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /V "Start" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /V "Start" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /V "Start" /T "REG_DWORD" /D "0" /F
)

::::::::::::::::::::
ECHO Disabling Tasks
::::::::::::::::::::

SchTasks /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuaRD MDM policy Refresh" /Disable
SchTasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable
SchTasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable
SchTasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable
SchTasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable

:::::::::::::::::::::::::::
ECHO Disabling Systray icon
:::::::::::::::::::::::::::

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /V "SecurityHealth"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /V "SecurityHealth" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /V "SecurityHealth"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /V "SecurityHealth" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /V "SecurityHealth"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /V "SecurityHealth" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /V "SecurityHealth"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /V "SecurityHealth" /F
)

::::::::::::::::::::::::::
ECHO Removing Context menu
::::::::::::::::::::::::::

REG Query "HKCR\*\shellex\ContextMenuHandlers\EPP"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /F
)

REG Query "HKCR\Directory\shellex\ContextMenuHandlers\EPP"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /F
)

REG Query "HKCR\Drive\shellex\ContextMenuHandlers\EPP"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /F
)

:::::::::::::::::::::::
ECHO Disabling Services
:::::::::::::::::::::::

REG Query "HKLM\System\CurrentControlSet\Services\WdBoot" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\System\CurrentControlSet\Services\WdBoot" /V "Start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\System\CurrentControlSet\Services\MDCoreSvc" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\System\CurrentControlSet\Services\MDCoreSvc" /V "Start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\System\CurrentControlSet\Services\WdFilter" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\System\CurrentControlSet\Services\WdFilter" /V "Start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\System\CurrentControlSet\Services\WdNisDrv" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\System\CurrentControlSet\Services\WdNisDrv" /V "Start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\System\CurrentControlSet\Services\WdNisSvc" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\System\CurrentControlSet\Services\WdNisSvc" /V "Start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\System\CurrentControlSet\Services\WinDefend" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\System\CurrentControlSet\Services\WinDefend" /V "Start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKCU\System\CurrentControlSet\Services\WdBoot" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\System\CurrentControlSet\Services\WdBoot" /V "Start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKCU\System\CurrentControlSet\Services\MDCoreSvc" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\System\CurrentControlSet\Services\MDCoreSvc" /V "Start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKCU\System\CurrentControlSet\Services\WdFilter" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\System\CurrentControlSet\Services\WdFilter" /V "Start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKCU\System\CurrentControlSet\Services\WdNisDrv" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\System\CurrentControlSet\Services\WdNisDrv" /V "Start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKCU\System\CurrentControlSet\Services\WdNisSvc" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\System\CurrentControlSet\Services\WdNisSvc" /V "Start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKCU\System\CurrentControlSet\Services\WinDefend" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\System\CurrentControlSet\Services\WinDefend" /V "Start" /T "REG_DWORD" /D "4" /F
)

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling Web Threat Defense Service (Phishing protection)
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

SC Stop "webthreatdefsvc"
SC Config "webthreatdefsvc" Start=Disabled

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling Web Threat Defense User Service (Phishing protection)
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

SC Stop "webthreatdefusersvc"
SC Config "webthreatdefusersvc" Start=Disabled

::::::::::::::::::::::::::::::::::
ECHO Disabling Windows SmartScreen
::::::::::::::::::::::::::::::::::

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /V "SmartScreenEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /V "SmartScreenEnabled" /T "REG_SZ" /D "Off" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /V "SmartScreenEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /V "SmartScreenEnabled" /T "REG_SZ" /D "Off" /F 
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /V "SmartScreenEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /V "SmartScreenEnabled" /T "REG_SZ" /D "Off" /F 
)

REG Query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer" /V "SmartScreenEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer" /V "SmartScreenEnabled" /T "REG_SZ" /D "Off" /F 
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /V "EnableWebContentEvaluation"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /V "EnableWebContentEvaluation" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /V "EnableSmartScreen"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /V "EnableSmartScreen" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /V "SmartScreenEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /V "SmartScreenEnabled" /T "REG_SZ" /D "Off" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /V "SmartScreenEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /V "SmartScreenEnabled" /T "REG_SZ" /D "Off" /F 
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /V "SmartScreenEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /V "SmartScreenEnabled" /T "REG_SZ" /D "Off" /F 
)

REG Query "HKCU\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer" /V "SmartScreenEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer" /V "SmartScreenEnabled" /T "REG_SZ" /D "Off" /F 
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /V "EnableWebContentEvaluation"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /V "EnableWebContentEvaluation" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\System" /V "EnableSmartScreen"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\System" /V "EnableSmartScreen" /T "REG_DWORD" /D "0" /F
)

:::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling SmartScreen Filter in Microsoft Edge
:::::::::::::::::::::::::::::::::::::::::::::::::::

REG Query "HKLM\Software\Microsoft\Edge\SmartScreenEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Edge\SmartScreenEnabled" /VE /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Edge\SmartScreenEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Edge\SmartScreenEnabled" /VE /T "REG_DWORD" /D "0" /F
)

::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling SmartScreen PUA in Microsoft Edge
:::::::::::::::::::::::::::::::::::::::::::::::::

REG Query "HKLM\Software\Microsoft\Edge\SmartScreenPuaEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Edge\SmartScreenPuaEnabled" /VE /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Edge\SmartScreenPuaEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Edge\SmartScreenPuaEnabled" /VE /T "REG_DWORD" /D "0" /F
)

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling Windows SmartScreen for Windows Store Apps
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\AppHost" /V "EnableWebContentEvaluation"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\AppHost" /V "EnableWebContentEvaluation" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /V "EnableWebContentEvaluation"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /V "EnableWebContentEvaluation" /T "REG_DWORD" /D "0" /F
)

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Removing Smartscreen (to restore run "SFC /ScanNow")
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::

TakeOwn /S "%computername%" /U "%username%" /F "%WinDir%\System32\smartscreen.exe"
icacls "%WinDir%\System32\smartscreen.exe" /grant:r %username%:f
TaskKill /IM "smartscreen.exe" /F
DEL "%WinDir%\System32\smartscreen.exe" /S /F /Q

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling Smart App Control blocking legitimate apps
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /V "VerifiedAndReputablePolicyState"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /V "VerifiedAndReputablePolicyState" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender" /V "VerifiedAndReputablePolicyState"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender" /V "VerifiedAndReputablePolicyState" /T "REG_DWORD" /D "0" /F
)

:::::::::::::::::::::::::::::::::::::::::
ECHO Other Registries and finishing setup
:::::::::::::::::::::::::::::::::::::::::

REG Query "HKLM\Software\Microsoft\Windows Defender\Features" /V "TamperProtection"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows Defender\Features" /V "TamperProtection" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\System\CurrentControlSet\Control\CI\Policy" /V "PUAProtection"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\System\CurrentControlSet\Control\CI\Policy" /V "PUAProtection" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\System\CurrentControlSet\Control\CI\Policy" /V "PUAProtection"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\System\CurrentControlSet\Control\CI\Policy" /V "PUAProtection" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\System\CurrentControlSet\Control\CI\Policy" /V "DisableAntiSpyware"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\System\CurrentControlSet\Control\CI\Policy" /V "DisableAntiSpyware" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\System\CurrentControlSet\Control\CI\Policy" /V "DisableAntiVirus"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\System\CurrentControlSet\Control\CI\Policy" /V "DisableAntiVirus" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V "SettingsPageVisibility"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V "SettingsPageVisibility" /T "REG_SZ" /D "hide:home" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /V "Start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /V "Start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" /V "Start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /V "Start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SamSs" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SamSs" /V "Start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wscsvc" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wscsvc" /V "Start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SgrmBroker" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SgrmBroker" /V "Start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /V "Start" /T "REG_DWORD" /D "4" /F
)

NET Stop "Sense"
NET Stop "WdFilter"
NET Stop "WdNisSvc"
NET Stop "WinDefend"

REG Query "HKLM\SOFTWARE\Microsoft\Windows Defender" /V "DisableAntiVirus"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows Defender" /V "DisableAntiVirus" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows Defender" /V "DisablDisableAntiSpywareeAntiVirus"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows Defender" /V "DisableAntiSpyware" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows Defender" /V "DisableRoutinelyTakingAction"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows Defender" /V "DisableRoutinelyTakingAction" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows Defender" /V "OneTimeSqmDataSent"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows Defender" /V "OneTimeSqmDataSent" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SpyNetReporting"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SpyNetReporting" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SubmitSamplesConsent"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SubmitSamplesConsent" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableBehaviorMonitoring"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableBehaviorMonitoring" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableOnAccessProtection"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableOnAccessProtection" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableScanOnRealtimeEnable"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableScanOnRealtimeEnable" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableRealtimeMonitoring"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableRealtimeMonitoring" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows Defender\UX Configuration" /V "DisablePrivacyMode"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows Defender\UX Configuration" /V "DisablePrivacyMode" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows Defender\UX Configuration" /V "DisablePrivacyMode"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows Defender\UX Configuration" /V "DisablePrivacyMode" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows Defender\Scan" /V "AutomaticallyCleanAfterScan"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows Defender\Scan" /V "AutomaticallyCleanAfterScan" /T "REG_DWORD" /D "0" /F
)

SchTasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable
SchTasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable
SchTasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable
SchTasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable

REG Query "HKLM\SOFTWARE\Policies\Microsoft\MRT" /V "DontOfferThroughWUAU"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /V "DontOfferThroughWUAU" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\MRT" /V "DontReportInfectionInformation"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /V "DontReportInfectionInformation" /T "REG_DWORD" /D "2" /F
)

Regsvr32 /S /U "%ProgramFiles%\Windows Defender\shellext.dll"

REG Query "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /V "DisableAntiSpywareRealtimeProtection"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /V "DisableAntiSpywareRealtimeProtection" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /V "DisableRealtimeMonitoring"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /V "DisableRealtimeMonitoring" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /V "DpaDisabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /V "DpaDisabled" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows Defender" /V "ProductStatus"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows Defender" /V "ProductStatus" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows Defender" /V "ManagedDefenderProductType"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows Defender" /V "ManagedDefenderProductType" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\MRT" /V "DontReportInfectionInformation"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /V "DontReportInfectionInformation" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /V "Start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKCU\Software\Microsoft\Windows Defender\Features" /V "TamperProtection"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows Defender\Features" /V "TamperProtection" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\System\CurrentControlSet\Control\CI\Policy" /V "PUAProtection"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\System\CurrentControlSet\Control\CI\Policy" /V "PUAProtection" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\System\CurrentControlSet\Control\CI\Policy" /V "PUAProtection"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\System\CurrentControlSet\Control\CI\Policy" /V "PUAProtection" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\System\CurrentControlSet\Control\CI\Policy" /V "DisableAntiSpyware"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\System\CurrentControlSet\Control\CI\Policy" /V "DisableAntiSpyware" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\System\CurrentControlSet\Control\CI\Policy" /V "DisableAntiVirus"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\System\CurrentControlSet\Control\CI\Policy" /V "DisableAntiVirus" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V "SettingsPageVisibility"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V "SettingsPageVisibility" /T "REG_SZ" /D "hide:home" /F
)

REG Query "HKCU\SYSTEM\CurrentControlSet\Services\Sense" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SYSTEM\CurrentControlSet\Services\Sense" /V "Start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WdNisSvc" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WdNisSvc" /V "Start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WdFilter" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WdFilter" /V "Start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WinDefend" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WinDefend" /V "Start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SamSs" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SamSs" /V "Start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKCU\SYSTEM\CurrentControlSet\Services\wscsvc" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SYSTEM\CurrentControlSet\Services\wscsvc" /V "Start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SgrmBroker" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SgrmBroker" /V "Start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /V "Start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows Defender" /V "DisableAntiVirus"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows Defender" /V "DisableAntiVirus" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows Defender" /V "DisablDisableAntiSpywareeAntiVirus"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows Defender" /V "DisableAntiSpyware" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows Defender" /V "DisableRoutinelyTakingAction"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows Defender" /V "DisableRoutinelyTakingAction" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows Defender" /V "OneTimeSqmDataSent"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows Defender" /V "OneTimeSqmDataSent" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SpyNetReporting"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SpyNetReporting" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SubmitSamplesConsent"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SubmitSamplesConsent" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableBehaviorMonitoring"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableBehaviorMonitoring" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableOnAccessProtection"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableOnAccessProtection" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableScanOnRealtimeEnable"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableScanOnRealtimeEnable" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableRealtimeMonitoring"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableRealtimeMonitoring" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows Defender\UX Configuration" /V "DisablePrivacyMode"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows Defender\UX Configuration" /V "DisablePrivacyMode" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows Defender\UX Configuration" /V "DisablePrivacyMode"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows Defender\UX Configuration" /V "DisablePrivacyMode" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows Defender\Scan" /V "AutomaticallyCleanAfterScan"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows Defender\Scan" /V "AutomaticallyCleanAfterScan" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\MRT" /V "DontOfferThroughWUAU"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\MRT" /V "DontOfferThroughWUAU" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\MRT" /V "DontReportInfectionInformation"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\MRT" /V "DontReportInfectionInformation" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /V "DisableAntiSpywareRealtimeProtection"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /V "DisableAntiSpywareRealtimeProtection" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /V "DisableRealtimeMonitoring"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /V "DisableRealtimeMonitoring" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /V "DpaDisabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /V "DpaDisabled" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows Defender" /V "ProductStatus"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows Defender" /V "ProductStatus" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows Defender" /V "ManagedDefenderProductType"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows Defender" /V "ManagedDefenderProductType" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\MRT" /V "DontReportInfectionInformation"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\MRT" /V "DontReportInfectionInformation" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /V "Start" /T "REG_DWORD" /D "4" /F
)

:::::::::::::::::::::::::::::::
ECHO Disabling Windows Firewall
:::::::::::::::::::::::::::::::

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\mpssvc" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\mpssvc" /V "Start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\BFE" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\BFE" /V "Start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /V "EnableFirewall"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /V "EnableFirewall" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /V "DisableNotifications"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /V "DisableNotifications" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /V "DoNotAllowExceptions"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /V "DoNotAllowExceptions" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /V "EnableFirewall"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /V "EnableFirewall" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /V "DisableNotifications"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /V "DisableNotifications" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /V "DoNotAllowExceptions"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /V "DoNotAllowExceptions" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /V "EnableFirewall"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /V "EnableFirewall" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /V "DisableNotifications"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /V "DisableNotifications" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /V "DoNotAllowExceptions"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /V "DoNotAllowExceptions" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SYSTEM\CurrentControlSet\Services\mpssvc" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SYSTEM\CurrentControlSet\Services\mpssvc" /V "Start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKCU\SYSTEM\CurrentControlSet\Services\BFE" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SYSTEM\CurrentControlSet\Services\BFE" /V "Start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /V "EnableFirewall"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /V "EnableFirewall" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /V "DisableNotifications"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /V "DisableNotifications" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /V "DoNotAllowExceptions"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /V "DoNotAllowExceptions" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /V "EnableFirewall"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /V "EnableFirewall" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /V "DisableNotifications"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /V "DisableNotifications" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /V "DoNotAllowExceptions"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /V "DoNotAllowExceptions" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /V "EnableFirewall"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /V "EnableFirewall" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /V "DisableNotifications"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /V "DisableNotifications" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /V "DoNotAllowExceptions"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /V "DoNotAllowExceptions" /T "REG_DWORD" /D "1" /F
)

:::::::::::::::::::::::::::::::::::::
ECHO Disabling watson malware reports
:::::::::::::::::::::::::::::::::::::

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /V "DisableGenericReports"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /V "DisableGenericReports" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /V "DisableGenericReports"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /V "DisableGenericReports" /T "REG_DWORD" /D "2" /F
)

::::::::::::::::::::::::::::::::::::::
ECHO Disabling malware diagnostic data
::::::::::::::::::::::::::::::::::::::

REG Query "HKLM\SOFTWARE\Policies\Microsoft\MRT" /V "DontReportInfectionInformation"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /V "DontReportInfectionInformation" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\MRT" /V "DontReportInfectionInformation"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\MRT" /V "DontReportInfectionInformation" /T "REG_DWORD" /D "2" /F
)

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling setting override for reporting to Microsoft MAPS
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "LocalSettingOverrideSpynetReporting"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "LocalSettingOverrideSpynetReporting" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "LocalSettingOverrideSpynetReporting"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "LocalSettingOverrideSpynetReporting" /T "REG_DWORD" /D "0" /F
)

::::::::::::::::::::::::::::::::::::::::
ECHO Disabling spynet Defender reporting
::::::::::::::::::::::::::::::::::::::::

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SpynetReporting"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SpynetReporting" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SpynetReporting"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SpynetReporting" /T "REG_DWORD" /D "0" /F
)

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling sending malware samples for further analysis
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SubmitSamplesConsent"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SubmitSamplesConsent" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SubmitSamplesConsent"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SubmitSamplesConsent" /T "REG_DWORD" /D "2" /F
)


ECHO .
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Auto-install subscribed/suggested apps :::::
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO .

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "ContentDeliveryAllowed"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "ContentDeliveryAllowed" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "FeaturemanagementEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "FeaturemanagementEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "OemPreInstalledAppsEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "OemPreInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEverEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEverEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SilentInstalledAppsEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SilentInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SoftLandingEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SoftLandingEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContentEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContentEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-310093Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-310093Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338388Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338388Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338389Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338389Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338393Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338393Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353694Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353694Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353696Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353696Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContentEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContentEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SystemPaneSuggestionsEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SystemPaneSuggestionsEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /V "DODownloadMode"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /V "DODownloadMode" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Policies\Microsoft\Windows\DeliveryOptimization" /V "DODownloadMode"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Policies\Microsoft\Windows\DeliveryOptimization" /V "DODownloadMode" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Policies\Microsoft\PushToInstall" /V "DisablePushToInstall"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Policies\Microsoft\PushToInstall" /V "DisablePushToInstall" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\Software\Policies\Microsoft\MRT" /V "DontOfferThroughWUAU"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Policies\Microsoft\MRT" /V "DontOfferThroughWUAU" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "ContentDeliveryAllowed"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "ContentDeliveryAllowed" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "FeaturemanagementEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "FeaturemanagementEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "OemPreInstalledAppsEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "OemPreInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEverEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEverEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SilentInstalledAppsEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SilentInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SoftLandingEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SoftLandingEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContentEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContentEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-310093Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-310093Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338388Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338388Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338389Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338389Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338393Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338393Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353694Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353694Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353696Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353696Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContentEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContentEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SystemPaneSuggestionsEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SystemPaneSuggestionsEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /V "DODownloadMode"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /V "DODownloadMode" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Policies\Microsoft\Windows\DeliveryOptimization" /V "DODownloadMode"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Policies\Microsoft\Windows\DeliveryOptimization" /V "DODownloadMode" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Policies\Microsoft\PushToInstall" /V "DisablePushToInstall"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Policies\Microsoft\PushToInstall" /V "DisablePushToInstall" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Policies\Microsoft\MRT" /V "DontOfferThroughWUAU"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Policies\Microsoft\MRT" /V "DontOfferThroughWUAU" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /F
)


ECHO .
ECHO :::::::::::::::::::::::::::::::
ECHO ::::: Disabling BitLocker :::::
ECHO :::::::::::::::::::::::::::::::
ECHO .

REG Query "HKLM\SYSTEM\CurrentControlSet\Control\BitLocker" /V "PreventDeviceEncryption"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Control\BitLocker" /V "PreventDeviceEncryption" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SYSTEM\CurrentControlSet\Control\BitLocker" /V "PreventDeviceEncryption"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SYSTEM\CurrentControlSet\Control\BitLocker" /V "PreventDeviceEncryption" /T "REG_DWORD" /D "1" /F
)


ECHO .
ECHO :::::::::::::::::::::::::::::::
ECHO ::::: Disabling Chat Icon :::::
ECHO :::::::::::::::::::::::::::::::
ECHO .

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows" /V "ChatIcon"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows" /V "ChatIcon" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "TaskbarMn"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "TaskbarMn" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows" /V "ChatIcon"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows" /V "ChatIcon" /T "REG_DWORD" /D "3" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "TaskbarMn"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "TaskbarMn" /T "REG_DWORD" /D "0" /F
)


ECHO .
ECHO :::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Hibernation :::::
ECHO :::::::::::::::::::::::::::::::::
ECHO .

REG Query "HKLM\System\CurrentControlSet\Control\Session Manager\Power" /V "HibernateEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\System\CurrentControlSet\Control\Session Manager\Power" /V "HibernateEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /V "ShowHibernateOption"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /V "ShowHibernateOption" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /V "HiberbootEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /V "HiberbootEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\System\CurrentControlSet\Control\Session Manager\Power" /V "HibernateEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\System\CurrentControlSet\Control\Session Manager\Power" /V "HibernateEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /V "ShowHibernateOption"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /V "ShowHibernateOption" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /V "HiberbootEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /V "HiberbootEnabled" /T "REG_DWORD" /D "0" /F
)

powercfg.exe /hibernate off
powercfg /hibernate off
powercfg -h off

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

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /V "MiscPolicyInfo"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /V "MiscPolicyInfo" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /V "PassedPolicy"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /V "PassedPolicy" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /V ShippedWithReserves
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /V "ShippedWithReserves" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /V "MiscPolicyInfo"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /V "MiscPolicyInfo" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /V "PassedPolicy"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /V "PassedPolicy" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /V "ShippedWithReserves"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /V "ShippedWithReserves" /T "REG_DWORD" /D "0" /F
)

fsutil storagereserve query C:
DISM /Online /Set-ReservedStorageState /State:Disabled /Quiet /NoRestart


ECHO .
ECHO ::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling NTFS Last Access :::::
ECHO ::::::::::::::::::::::::::::::::::::::
ECHO .

REG Query "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /V "NtfsDisableLastAccessUpdate"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /V "NtfsDisableLastAccessUpdate" /T "REG_DWORD" /D "80000001" /F
)

REG Query "HKCU\SYSTEM\CurrentControlSet\Control\FileSystem" /V "NtfsDisableLastAccessUpdate"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SYSTEM\CurrentControlSet\Control\FileSystem" /V "NtfsDisableLastAccessUpdate" /T "REG_DWORD" /D "80000001" /F
)

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

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /V "Disabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /V "Disabled" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /V "Disabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /V "Disabled" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /V "Disabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /V "Disabled" /T "REG_DWORD" /D "1" /F
)


REG Query "HKCU\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /V "Disabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /V "Disabled" /T "REG_DWORD" /D "1" /F
)

:::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling Microsoft Support Diagnostic Tool MSDT
:::::::::::::::::::::::::::::::::::::::::::::::::::::

REG Query "HKLM\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /V "DisableQueryremoteServer"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /V "DisableQueryremoteServer" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /V "EnableQueryremoteServer"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /V "EnableQueryremoteServer" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /V "DisableQueryremoteServer"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /V "DisableQueryremoteServer" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /V "EnableQueryremoteServer"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /V "EnableQueryremoteServer" /T "REG_DWORD" /D "0" /F
)

::::::::::::::::::::::::::::::
ECHO Disabling System Debugger
::::::::::::::::::::::::::::::

REG Query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AeDebug" /V "Auto"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AeDebug" /V "Auto" /T "REG_SZ" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\AeDebug" /V "Auto"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\AeDebug" /V "Auto" /T "REG_SZ" /D "0" /F
)

::::::::::::::::::::::::::::::::::::::
ECHO Disabling Windows Error Reporting
::::::::::::::::::::::::::::::::::::::

REG Query "HKLM\Software\Microsoft\PCHealth\ErrorReporting" /V "DoReport"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\PCHealth\ErrorReporting" /V "DoReport" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /V "Disabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /V "Disabled" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /V "Disabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /V "Disabled" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /V "Disabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /V "Disabled" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Microsoft\PCHealth\ErrorReporting" /V "DoReport"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\PCHealth\ErrorReporting" /V "DoReport" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /V "Disabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /V "Disabled" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /V "Disabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /V "Disabled" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Policies\Microsoft\Windows\Windows Error Reporting" /V "Disabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Policies\Microsoft\Windows\Windows Error Reporting" /V "Disabled" /T "REG_DWORD" /D "1" /F
)

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO DefaultConsent / 1 - Always ask (default) / 2 - Parameters only / 3 - Parameters and safe data / 4 - All data
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

REG Query "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /V "DefaultConsent"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /V "DefaultConsent" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /V "DefaultOverrideBehavior"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /V "DefaultOverrideBehavior" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /V "DefaultConsent"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /V "DefaultConsent" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /V "DefaultOverrideBehavior"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /V "DefaultOverrideBehavior" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Microsoft\Windows\Windows Error Reporting\Consent" /V "DefaultConsent"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting\Consent" /V "DefaultConsent" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\Windows Error Reporting\Consent" /V "DefaultOverrideBehavior"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting\Consent" /V "DefaultOverrideBehavior" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Microsoft\Windows\Windows Error Reporting\Consent" /V "DefaultConsent"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting\Consent" /V "DefaultConsent" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\Windows Error Reporting\Consent" /V "DefaultOverrideBehavior"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting\Consent" /V "DefaultOverrideBehavior" /T "REG_DWORD" /D "1" /F
)

::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling WER sending second-level data
::::::::::::::::::::::::::::::::::::::::::::

REG Query "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /V "DontSendAdditionalData"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /V "DontSendAdditionalData" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /V "DontSendAdditionalData"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /V "DontSendAdditionalData" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /V "DontSendAdditionalData"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /V "DontSendAdditionalData" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /V "DontSendAdditionalData"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /V "DontSendAdditionalData" /T "REG_DWORD" /D "1" /F
)

::::::::::::::::::::::::::::::::::::::::
ECHO Disabling WER crash dialogs, popups
::::::::::::::::::::::::::::::::::::::::

REG Query "HKLM\Software\Microsoft\PCHealth\ErrorReporting" /V "ShowUI"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\PCHealth\ErrorReporting" /V "ShowUI" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /V "DontShowUI"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /V "DontShowUI" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /V "DontShowUI"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /V "DontShowUI" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Microsoft\PCHealth\ErrorReporting" /V "ShowUI"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\PCHealth\ErrorReporting" /V "ShowUI" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /V "DontShowUI"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /V "DontShowUI" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /V "DontShowUI"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /V "DontShowUI" /T "REG_DWORD" /D "1" /F
)

::::::::::::::::::::::::::
ECHO Disabling WER logging
::::::::::::::::::::::::::

REG Query "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /V "LoggingDisabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /V "LoggingDisabled" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /V "LoggingDisabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /V "LoggingDisabled" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /V "LoggingDisabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /V "LoggingDisabled" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /V "LoggingDisabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /V "LoggingDisabled" /T "REG_DWORD" /D "1" /F
)

SchTasks /Change /TN "Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" /Disable
SchTasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable


ECHO .
ECHO ::::::::::::::::::::::::::::::::::::
ECHO ::::: Windows Explorer Options :::::
ECHO ::::::::::::::::::::::::::::::::::::
ECHO .

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /V "PeopleBand"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /V "PeopleBand" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /V "LongPathsEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /V "LongPathsEnabled" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /V "PeopleBand"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /V "PeopleBand" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SYSTEM\CurrentControlSet\Control\FileSystem" /V "LongPathsEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SYSTEM\CurrentControlSet\Control\FileSystem" /V "LongPathsEnabled" /T "REG_DWORD" /D "1" /F
)

::::::::::::::::::::::::::::::::::::::::::
ECHO Setting Open File Explorer to This PC
::::::::::::::::::::::::::::::::::::::::::

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "LaunchTo"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "LaunchTo" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "LaunchTo"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "LaunchTo" /T "REG_DWORD" /D "1" /F
)

::::::::::::::::::::::::::::::::::::
ECHO Disabling recently used folders
::::::::::::::::::::::::::::::::::::

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /V "ShowRecent"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /V "ShowRecent" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /V "ShowRecent"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /V "ShowRecent" /T "REG_DWORD" /D "0" /F
)

::::::::::::::::::::::::::::::::::::::
ECHO Disabling frequently used folders
::::::::::::::::::::::::::::::::::::::

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /V "ShowFrequent"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /V "ShowFrequent" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /V "ShowFrequent"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /V "ShowFrequent" /T "REG_DWORD" /D "0" /F
)

:::::::::::::::::::::::::::::::::::::::::
ECHO Disabling Show files from Office.com
:::::::::::::::::::::::::::::::::::::::::

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /V "ShowCloudFilesInQuickAccess"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /V "ShowCloudFilesInQuickAccess" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /V "ShowCloudFilesInQuickAccess"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /V "ShowCloudFilesInQuickAccess" /T "REG_DWORD" /D "0" /F
)

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling Network Icon from Navigation Panel / Right in Nav Panel
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

REG Query "HKCR\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\ShellFolder" /V "Attributes"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCR\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\ShellFolder" /V "Attributes" /T "REG_DWORD" /D "2962489444" /F
)

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Removing Gallery from Navigation Pane in File Explorer
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

REG Query "HKLM\Software\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" /V "System.IsPinnedToNameSpaceTree"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" /V "System.IsPinnedToNameSpaceTree" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" /V "System.IsPinnedToNameSpaceTree"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" /V "System.IsPinnedToNameSpaceTree" /T "REG_DWORD" /D "0" /F
)

:::::::::::::::::::::::::::::::::::::
ECHO Removing 3D Folders from This PC
:::::::::::::::::::::::::::::::::::::

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /F
)

::::::::::::::::::::::::::::::::::::::::::::::
ECHO Removing Home (Quick access) from This PC
::::::::::::::::::::::::::::::::::::::::::::::

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /V "HubMode"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /V "HubMode" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /F
)

REG Query "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /V "HubMode"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /V "HubMode" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /F
)

REG Query "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /F
)

::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Setting Show hidden files, folders and drives
::::::::::::::::::::::::::::::::::::::::::::::::::

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "Hidden"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "Hidden" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "Hidden"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "Hidden" /T "REG_DWORD" /D "1" /F
)

:::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Setting Show extensions for known file types
:::::::::::::::::::::::::::::::::::::::::::::::::

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "HideFileExt"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "HideFileExt" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "HideFileExt"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "HideFileExt" /T "REG_DWORD" /D "0" /F
)

::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO setting Always show more details in copy dialog
::::::::::::::::::::::::::::::::::::::::::::::::::::

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /V "EnthusiastMode"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /V "EnthusiastMode" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /V "EnthusiastMode"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /V "EnthusiastMode" /T "REG_DWORD" /D "1" /F
)


ECHO .
ECHO :::::::::::::::::::::::::::::::
ECHO ::::: Disabling Telemetry :::::
ECHO :::::::::::::::::::::::::::::::
ECHO .

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /V "AllowTelemetry"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /V "AllowTelemetry" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /V "AllowTelemetry"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /V "AllowTelemetry" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\Privacy" /V "TailoredExperiencesWithDiagnosticDataEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Privacy" /V "TailoredExperiencesWithDiagnosticDataEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /V "HasAccepted"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /V "HasAccepted" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Input\TIPC" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Input\TIPC" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\InputPersonalization" /V "RestrictImplicitInkCollection"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\InputPersonalization" /V "RestrictImplicitInkCollection" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\Software\Microsoft\InputPersonalization" /V "RestrictImplicitTextCollection"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\InputPersonalization" /V "RestrictImplicitTextCollection" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\Software\Microsoft\InputPersonalization\TrainedDataStore" /V "HarvestContacts"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\InputPersonalization\TrainedDataStore" /V "HarvestContacts" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Personalization\Settings" /V "AcceptedPrivacyPolicy"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Personalization\Settings" /V "AcceptedPrivacyPolicy" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /V "AllowTelemetry"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /V "AllowTelemetry" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" /V "ChatIcon"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" /V "ChatIcon" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "TaskbarMn"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "TaskbarMn" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /V "NoGenTicket"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /V "NoGenTicket" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\MediaPlayer\Preferences" /V "UsageTracking"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\MediaPlayer\Preferences" /V "UsageTracking" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\15.0\osm" /V "enablefileobfuscation"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\15.0\osm" /V "enablefileobfuscation" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\15.0\osm" /V "enablelogging"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\15.0\osm" /V "enablelogging" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\15.0\osm" /V "enableupload"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\15.0\osm" /V "enableupload" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common" /V "qmenable"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common" /V "qmenable" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common" /V "sendcustomerdata"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common" /V "sendcustomerdata" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common" /V "updatereliabilitydata"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common" /V "updatereliabilitydata" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" /V "enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" /V "enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" /V "includescreenshot"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" /V "includescreenshot" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\internet" /V "useonlinecontent"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\internet" /V "useonlinecontent" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\ptwatson" /V "ptwoptin"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\ptwatson" /V "ptwoptin" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm" /V "enablefileobfuscation"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm" /V "enablefileobfuscation" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm" /V "enablelogging"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm" /V "enablelogging" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm" /V "enableupload"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm" /V "enableupload" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "accesssolution"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "accesssolution" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "olksolution"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "olksolution" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "onenotesolution"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "onenotesolution" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "pptsolution"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "pptsolution" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "projectsolution"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "projectsolution" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "publishersolution"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "publishersolution" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "visiosolution"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "visiosolution" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "wdsolution"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "wdsolution" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "xlsolution"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "xlsolution" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "agave"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "agave" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "appaddins"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "appaddins" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "comaddins"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "comaddins" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "documentfiles"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "documentfiles" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "templatefiles"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "templatefiles" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" /V "blockcontentexecutionfrominternet"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" /V "blockcontentexecutionfrominternet" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /V "level"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /V "level" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" /V "blockcontentexecutionfrominternet"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" /V "blockcontentexecutionfrominternet" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\word\security" /V "blockcontentexecutionfrominternet"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\word\security" /V "blockcontentexecutionfrominternet" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /V "AllowTelemetry"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /V "AllowTelemetry" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /V "AllowTelemetry"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /V "AllowTelemetry" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /V "TailoredExperiencesWithDiagnosticDataEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /V "TailoredExperiencesWithDiagnosticDataEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /V "HasAccepted"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /V "HasAccepted" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Input\TIPC" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Input\TIPC" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\InputPersonalization" /V "RestrictImplicitInkCollection"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\InputPersonalization" /V "RestrictImplicitInkCollection" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Microsoft\InputPersonalization" /V "RestrictImplicitTextCollection"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\InputPersonalization" /V "RestrictImplicitTextCollection" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /V "HarvestContacts"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /V "HarvestContacts" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Personalization\Settings" /V "AcceptedPrivacyPolicy"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Personalization\Settings" /V "AcceptedPrivacyPolicy" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /V "AllowTelemetry"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /V "AllowTelemetry" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" /V "ChatIcon"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" /V "ChatIcon" /T "REG_DWORD" /D "3" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "TaskbarMn"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "TaskbarMn" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /V "NoGenTicket"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /V "NoGenTicket" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /V "UsageTracking"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /V "UsageTracking" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\osm" /V "enablefileobfuscation"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\osm" /V "enablefileobfuscation" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\osm" /V "enablelogging"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\osm" /V "enablelogging" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\osm" /V "enableupload"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\osm" /V "enableupload" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common" /V "qmenable"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common" /V "qmenable" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common" /V "sendcustomerdata"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common" /V "sendcustomerdata" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common" /V "updatereliabilitydata"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common" /V "updatereliabilitydata" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" /V "enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" /V "enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" /V "includescreenshot"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" /V "includescreenshot" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\internet" /V "useonlinecontent"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\internet" /V "useonlinecontent" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\ptwatson" /V "ptwoptin"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\ptwatson" /V "ptwoptin" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm" /V "enablefileobfuscation"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm" /V "enablefileobfuscation" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm" /V "enablelogging"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm" /V "enablelogging" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm" /V "enableupload"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm" /V "enableupload" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "accesssolution"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "accesssolution" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "olksolution"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "olksolution" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "onenotesolution"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "onenotesolution" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "pptsolution"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "pptsolution" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "projectsolution"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "projectsolution" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "publishersolution"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "publishersolution" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "visiosolution"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "visiosolution" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "wdsolution"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "wdsolution" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "xlsolution"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "xlsolution" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "agave"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "agave" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "appaddins"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "appaddins" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "comaddins"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "comaddins" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "documentfiles"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "documentfiles" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "templatefiles"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "templatefiles" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" /V "blockcontentexecutionfrominternet"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" /V "blockcontentexecutionfrominternet" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /V "level"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /V "level" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" /V "blockcontentexecutionfrominternet"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" /V "blockcontentexecutionfrominternet" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security" /V "blockcontentexecutionfrominternet"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security" /V "blockcontentexecutionfrominternet" /T "REG_DWORD" /D "0" /F
)

SchTasks /Change /Disable /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
SchTasks /Change /Disable /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
SchTasks /Change /Disable /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
SchTasks /Change /Disable /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
SchTasks /Change /Disable /TN "\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents"
SchTasks /Change /Disable /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem"
SchTasks /Change /Disable /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting"

SETX POWERSHELL_TELEMETRY_OPTOUT 1


ECHO .
ECHO ::::::::::::::::::::::::::::::
ECHO ::::: Disabling OneDrive :::::
ECHO ::::::::::::::::::::::::::::::
ECHO .

:::::::::::::::::::::
ECHO Killing onedrive
:::::::::::::::::::::

TaskKill /F /IM "OneDrive.exe"

:::::::::::::::::::::::::::::::::
ECHO Running OneDrive uninstaller
:::::::::::::::::::::::::::::::::

if exist %SystemRoot%\System32\OneDriveSetup.exe (
	start /wait %SystemRoot%\System32\OneDriveSetup.exe /uninstall
) else (
	start /wait %SystemRoot%\SysWOW64\OneDriveSetup.exe /uninstall
)

::::::::::::::::::::::::::::::::::::::
ECHO Deleting OneDrive scheduled tasks
::::::::::::::::::::::::::::::::::::::

for /F "tokens=1 delims=," %%x in ('schtasks /Query /Fo csv ^| find "OneDrive"') do schtasks /Delete /TN %%x /F

::::::::::::::::::::::::::::::::
ECHO Removing OneDrive shortcuts
::::::::::::::::::::::::::::::::

DEL "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Microsoft OneDrive.lnk" /S /F /Q
DEL "%APPDATA%\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" /S /F /Q
DEL "%USERPROFILE%\Links\OneDrive.lnk" /S /F /Q

::::::::::::::::::::::::::::::::::::::::::
ECHO Removing OneDrive related directories
::::::::::::::::::::::::::::::::::::::::::

RD "%UserProfile%\OneDrive" /Q /S 
RD "%SystemDrive%\OneDriveTemp" /Q /s
RD "%LocalAppData%\Microsoft\OneDrive" /Q /s
RD "%ProgramData%\Microsoft OneDrive" /Q /s

::::::::::::::::::::::::::::::::::::::
ECHO Removing related registry folders
::::::::::::::::::::::::::::::::::::::

REG Query "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4308-9B53-224DE2ED1FE6}"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4308-9B53-224DE2ED1FE6}" /F
)

REG Query "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4308-9B53-224DE2ED1FE6}"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4308-9B53-224DE2ED1FE6}" /F
)

::::::::::::::::::::::
ECHO Disabling onesync
::::::::::::::::::::::

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /V "DisableFileSyncNGSC"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /V "DisableFileSyncNGSC" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /V "DisableFileSync"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /V "DisableFileSync" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /V "DisableMeteredNetworkFileSync"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /V "DisableMeteredNetworkFileSync" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /V "DisableLibrariesDefaultSaveToOneDrive"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /V "DisableLibrariesDefaultSaveToOneDrive" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\OneDrive" /V "DisablePersonalSync"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\OneDrive" /V "DisablePersonalSync" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /V "DisableFileSyncNGSC"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /V "DisableFileSyncNGSC" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /V "DisableFileSync"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /V "DisableFileSync" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /V "DisableMeteredNetworkFileSync"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /V "DisableMeteredNetworkFileSync" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /V "DisableLibrariesDefaultSaveToOneDrive"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /V "DisableLibrariesDefaultSaveToOneDrive" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\OneDrive" /V "DisablePersonalSync"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\OneDrive" /V "DisablePersonalSync" /T "REG_DWORD" /D "2" /F
)

:::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Removing onedrive from explorer/quick access
:::::::::::::::::::::::::::::::::::::::::::::::::

REG Query "HKCR\CLSID\{018D5C66-4533-4308-9B53-224DE2ED1FE6}" /V "System.IsPinnedToNameSpaceTree"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCR\CLSID\{018D5C66-4533-4308-9B53-224DE2ED1FE6}" /V "System.IsPinnedToNameSpaceTree" /T "REG_DWORD" /D "0" /F
)

REG Query "KCR\Wow6432Node\{018D5C66-4533-4308-9B53-224DE2ED1FE6}" /V "System.IsPinnedToNameSpaceTree"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCR\Wow6432Node\{018D5C66-4533-4308-9B53-224DE2ED1FE6}" /V "System.IsPinnedToNameSpaceTree" /T "REG_DWORD" /D "0" /F
)


ECHO .
ECHO ::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling location services  :::::
ECHO ::::::::::::::::::::::::::::::::::::::::
ECHO .

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /V "DisableWindowsLocationProvider"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /V "DisableWindowsLocationProvider" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /V "DisableLocationScripting"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /V "DisableLocationScripting" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /V "DisableLocation"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /V "DisableLocation" /D "1" /T "REG_DWORD" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /V "DisableWindowsLocationProvider"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /V "DisableWindowsLocationProvider" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /V "DisableLocationScripting"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /V "DisableLocationScripting" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /V "DisableLocation"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /V "DisableLocation" /D "1" /T "REG_DWORD" /F
)


ECHO .
ECHO ::::::::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Cloud Voice Recognation  :::::
ECHO ::::::::::::::::::::::::::::::::::::::::::::::
ECHO .

REG Query "HKLM\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /V "HasAccepted"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /V "HasAccepted" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /V "HasAccepted"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /V "HasAccepted" /T "REG_DWORD" /D "0" /F
)


ECHO .
ECHO ::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Bing in Start Menu :::::
ECHO ::::::::::::::::::::::::::::::::::::::::
ECHO .

REG Query "HKLM\Software\Policies\Microsoft\Windows\Explorer" /V "ShowRunAsDifferentUserInStart"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /V "ShowRunAsDifferentUserInStart" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\Software\Policies\Microsoft\Windows\Explorer" /V "DisableSearchBoxSuggestions"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /V "DisableSearchBoxSuggestions" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Policies\Microsoft\Windows\Explorer" /V "ShowRunAsDifferentUserInStart"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /V "ShowRunAsDifferentUserInStart" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Policies\Microsoft\Windows\Explorer" /V "DisableSearchBoxSuggestions"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /V "DisableSearchBoxSuggestions" /T "REG_DWORD" /D "1" /F
)


ECHO .
ECHO :::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Opting out from Windows privacy consent :::::
ECHO :::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO .

REG Query "HKLM\SOFTWARE\Microsoft\Personalization\Settings" /V "AcceptedPrivacyPolicy"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Personalization\Settings" /V "AcceptedPrivacyPolicy" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /V "AcceptedPrivacyPolicy"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /V "AcceptedPrivacyPolicy" /T "REG_DWORD" /D "0" /F
)


ECHO .
ECHO ::::::::::::::::::::::::::::
ECHO ::::: Disabling Search :::::
ECHO ::::::::::::::::::::::::::::
ECHO .

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "DisableremovableDriveIndexing"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "DisableremovableDriveIndexing" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "PreventUsingAdvancedIndexingOptions"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "PreventUsingAdvancedIndexingOptions" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\Search" /V "BingSearchEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Search" /V "BingSearchEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\Search" /V "CortanaEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Search" /V "CortanaEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowCloudSearch"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowCloudSearch" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchUseWeb"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchUseWeb" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchUseWebOverMeteredConnections"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchUseWebOverMeteredConnections" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "DisableWebSearch"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "DisableWebSearch" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowCortanaAboveLock"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowCortanaAboveLock" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\services\TermServicentVersion\Search" /V "AllowCortana"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\services\TermServicentVersion\Search" /V "AllowCortana" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowCortana"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowCortana" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowSearchToUseLocation"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowSearchToUseLocation" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowCortana"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowCortana" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowSearchToUseLocation"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowSearchToUseLocation" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchPrivacy"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchPrivacy" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchUseWeb"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchUseWeb" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchUseWebOverMeteredConnections"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchUseWebOverMeteredConnections" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "DisableWebSearch"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "DisableWebSearch" /T "REG_DWORD" /D "1" /F 
)

REG Query "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" /V "value"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" /V "value" /T "REG_DWORD" /D "0" /F 
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "CortanaEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "CortanaEnabled" /T "REG_DWORD" /D "0" /F 
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "BingSearchEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "BingSearchEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "CanCortanaBeEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "CanCortanaBeEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Personalization\Settings" /V "AcceptedPrivacyPolicy"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Personalization\Settings" /V "AcceptedPrivacyPolicy" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "DeviceHistoryEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "DeviceHistoryEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "HistoryViewEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "HistoryViewEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "DisableremovableDriveIndexing"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "DisableremovableDriveIndexing" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "PreventUsingAdvancedIndexingOptions"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "PreventUsingAdvancedIndexingOptions" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /V "BingSearchEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /V "BingSearchEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /V "CortanaEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /V "CortanaEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowCloudSearch"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowCloudSearch" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchUseWeb"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchUseWeb" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchUseWebOverMeteredConnections"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchUseWebOverMeteredConnections" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "DisableWebSearch"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "DisableWebSearch" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowCortanaAboveLock"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowCortanaAboveLock" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SYSTEM\CurrentControlSet\services\TermServicentVersion\Search" /V "AllowCortana"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SYSTEM\CurrentControlSet\services\TermServicentVersion\Search" /V "AllowCortana" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowCortana"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowCortana" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowSearchToUseLocation"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowSearchToUseLocation" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowCortana"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowCortana" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowSearchToUseLocation"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowSearchToUseLocation" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchPrivacy"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchPrivacy" /T "REG_DWORD" /D "3" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchUseWeb"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchUseWeb" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchUseWebOverMeteredConnections"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchUseWebOverMeteredConnections" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "DisableWebSearch"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "DisableWebSearch" /T "REG_DWORD" /D "1" /F 
)

REG Query "HKCU\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" /V "value"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" /V "value" /T "REG_DWORD" /D "0" /F 
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "CortanaEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "CortanaEnabled" /T "REG_DWORD" /D "0" /F 
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "BingSearchEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "BingSearchEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "CanCortanaBeEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "CanCortanaBeEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /V "AcceptedPrivacyPolicy"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /V "AcceptedPrivacyPolicy" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "DeviceHistoryEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "DeviceHistoryEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "HistoryViewEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "HistoryViewEnabled" /T "REG_DWORD" /D "0" /F
)


ECHO .
ECHO :::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling DevHome and Outlook :::::
ECHO :::::::::::::::::::::::::::::::::::::::::
ECHO .

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\OutlookUpdate" /V "workCompleted"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\OutlookUpdate" /V "workCompleted" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\DevHomeUpdate" /V "workCompleted"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\DevHomeUpdate" /V "workCompleted" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKLM\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKLM\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\OutlookUpdate" /V "workCompleted"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\OutlookUpdate" /V "workCompleted" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\DevHomeUpdate" /V "workCompleted"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\DevHomeUpdate" /V "workCompleted" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKCU\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKCU\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate" /F
)


ECHO .
ECHO ::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Sponsored apps :::::
ECHO ::::::::::::::::::::::::::::::::::::
ECHO .

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "OemPreInstalledAppsEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "OemPreInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SilentInstalledAppsEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SilentInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V "DisableWindowsConsumerFeatures"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V "DisableWindowsConsumerFeatures" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "ContentDeliveryAllowed"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "ContentDeliveryAllowed" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "FeatureManagementEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "FeatureManagementEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "OemPreInstalledAppsEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "OemPreInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEverEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEverEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SoftLandingEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SoftLandingEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContentEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContentEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-310093Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-310093Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338388Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338388Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338389Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338389Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338393Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338393Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353694Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353694Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353696Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353696Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContentEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContentEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SystemPaneSuggestionsEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SystemPaneSuggestionsEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\PushToInstall" /V "DisablePushToInstall"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\PushToInstall" /V "DisablePushToInstall" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\MRT" /V "DontOfferThroughWUAU"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /V "DontOfferThroughWUAU" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V "DisableConsumerAccountStateContent"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V "DisableConsumerAccountStateContent" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V "DisableCloudOptimizedContent"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V "DisableCloudOptimizedContent" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "OemPreInstalledAppsEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "OemPreInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SilentInstalledAppsEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SilentInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V "DisableWindowsConsumerFeatures"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V "DisableWindowsConsumerFeatures" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "ContentDeliveryAllowed"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "ContentDeliveryAllowed" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "FeatureManagementEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "FeatureManagementEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "OemPreInstalledAppsEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "OemPreInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEverEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEverEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SoftLandingEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SoftLandingEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContentEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContentEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-310093Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-310093Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338388Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338388Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338389Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338389Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338393Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338393Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353694Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353694Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353696Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353696Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContentEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContentEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SystemPaneSuggestionsEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SystemPaneSuggestionsEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\PushToInstall" /V "DisablePushToInstall"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\PushToInstall" /V "DisablePushToInstall" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\MRT" /V "DontOfferThroughWUAU"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\MRT" /V "DontOfferThroughWUAU" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V "DisableConsumerAccountStateContent"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V "DisableConsumerAccountStateContent" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V "DisableCloudOptimizedContent"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V "DisableCloudOptimizedContent" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /F
)


ECHO .
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Deleting App Compatibility Appraiser and Assistant :::::
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO .

REG Query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0600DD45-FAF2-4131-A006-0B17509B9F78}"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0600DD45-FAF2-4131-A006-0B17509B9F78}" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /V "DisablePCA"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /V "DisablePCA" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0600DD45-FAF2-4131-A006-0B17509B9F78}"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0600DD45-FAF2-4131-A006-0B17509B9F78}" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /V "DisablePCA"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /V "DisablePCA" /T "REG_DWORD" /D "2" /F
)


ECHO .
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Deleting Customer Experiment Improvement Program :::::
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO .

REG Query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{4738DE7A-BCC1-4E2D-B1B0-CADB044BFA81}"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{4738DE7A-BCC1-4E2D-B1B0-CADB044BFA81}" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{6FAC31FA-4A85-4E64-BFD5-2154FF4594B3}"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{6FAC31FA-4A85-4E64-BFD5-2154FF4594B3}" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{FC931F16-B50A-472E-B061-B6F79A71EF59}"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{FC931F16-B50A-472E-B061-B6F79A71EF59}" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /V "CEIPEnable"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /V "CEIPEnable" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client" /V "CEIP"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client" /V "CEIP" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\SQMClient" /V "CorporateSQMURL"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient" /V "CorporateSQMURL" /T "REG_SZ" /D "0.0.0.0" /F
)


REG Query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{4738DE7A-BCC1-4E2D-B1B0-CADB044BFA81}"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{4738DE7A-BCC1-4E2D-B1B0-CADB044BFA81}" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{6FAC31FA-4A85-4E64-BFD5-2154FF4594B3}"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{6FAC31FA-4A85-4E64-BFD5-2154FF4594B3}" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{FC931F16-B50A-472E-B061-B6F79A71EF59}"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{FC931F16-B50A-472E-B061-B6F79A71EF59}" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /V "CEIPEnable"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /V "CEIPEnable" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Messenger\Client" /V "CEIP"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Messenger\Client" /V "CEIP" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\SQMClient" /V "CorporateSQMURL"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\SQMClient" /V "CorporateSQMURL" /T "REG_SZ" /D "0.0.0.0" /F
)


ECHO .
ECHO :::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Deleting Program Data Updater :::::
ECHO :::::::::::::::::::::::::::::::::::::::::
ECHO .

REG Query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0671EB05-7D95-4153-A32B-1426B9FE61DB}"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0671EB05-7D95-4153-A32B-1426B9FE61DB}" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0671EB05-7D95-4153-A32B-1426B9FE61DB}"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0671EB05-7D95-4153-A32B-1426B9FE61DB}" /F
)


ECHO .
ECHO ::::::::::::::::::::::::::::::::::
ECHO ::::: Deleting autochk proxy :::::
ECHO ::::::::::::::::::::::::::::::::::
ECHO .

REG Query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{87BF85F4-2CE1-4160-96EA-52F554AA28A2}"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{87BF85F4-2CE1-4160-96EA-52F554AA28A2}" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{8A9C643C-3D74-4099-B6BD-9C6D170898B1}"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{8A9C643C-3D74-4099-B6BD-9C6D170898B1}" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{E3176A65-4E44-4ED3-AA73-3283660ACB9C}"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{E3176A65-4E44-4ED3-AA73-3283660ACB9C}" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{87BF85F4-2CE1-4160-96EA-52F554AA28A2}"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{87BF85F4-2CE1-4160-96EA-52F554AA28A2}" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{8A9C643C-3D74-4099-B6BD-9C6D170898B1}"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{8A9C643C-3D74-4099-B6BD-9C6D170898B1}" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{E3176A65-4E44-4ED3-AA73-3283660ACB9C}"
if %ERRORLEVEL% EQU 0 (
REG Delete "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{E3176A65-4E44-4ED3-AA73-3283660ACB9C}" /F
)


ECHO .
ECHO ::::::::::::::::::::::::::
ECHO ::::: Disabling XBOX :::::
ECHO ::::::::::::::::::::::::::
ECHO .

REG Query "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /V "value"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /V "value" /T "REG_SZ" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /V "AllowGameDVR"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /V "AllowGameDVR" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\System\GameConfigStore" /V "GameDVR_Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\System\GameConfigStore" /V "GameDVR_Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /V "value"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /V "value" /T "REG_SZ" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" /V "ActivationType"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" /V "ActivationType" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\System\GameConfigStore" /V "GameDVR_Enabled" /V "GameDVR_Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\System\GameConfigStore" /V "GameDVR_Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\System\GameConfigStore" /V "GameDVR_FSEBehaviorMode"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\System\GameConfigStore" /V "GameDVR_FSEBehaviorMode" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\System\GameConfigStore" /V "GameDVR_HonorUserFSEBehaviorMode"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\System\GameConfigStore" /V "GameDVR_HonorUserFSEBehaviorMode" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\System\GameConfigStore" /V "GameDVR_DXGIHonorFSEWindowsCompatible"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\System\GameConfigStore" /V "GameDVR_DXGIHonorFSEWindowsCompatible" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\System\GameConfigStore" /V "GameDVR_EFSEFeatureFlags"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\System\GameConfigStore" /V "GameDVR_EFSEFeatureFlags" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /V "value"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /V "value" /T "REG_SZ" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /V "AllowGameDVR"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /V "AllowGameDVR" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\System\GameConfigStore" /V "GameDVR_Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\System\GameConfigStore" /V "GameDVR_Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /V "value"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /V "value" /T "REG_SZ" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" /V "ActivationType"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" /V "ActivationType" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\System\GameConfigStore" /V "GameDVR_Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\System\GameConfigStore" /V "GameDVR_Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\System\GameConfigStore" /V "GameDVR_FSEBehaviorMode"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\System\GameConfigStore" /V "GameDVR_FSEBehaviorMode" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\System\GameConfigStore" /V "GameDVR_HonorUserFSEBehaviorMode"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\System\GameConfigStore" /V "GameDVR_HonorUserFSEBehaviorMode" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\System\GameConfigStore" /V "GameDVR_DXGIHonorFSEWindowsCompatible"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\System\GameConfigStore" /V "GameDVR_DXGIHonorFSEWindowsCompatible" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\System\GameConfigStore" /V "GameDVR_EFSEFeatureFlags"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\System\GameConfigStore" /V "GameDVR_EFSEFeatureFlags" /T "REG_DWORD" /D "0" /F
)


ECHO .
ECHO :::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Sync Settings :::::
ECHO :::::::::::::::::::::::::::::::::::
ECHO .

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /V "SyncPolicy"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /V "SyncPolicy" /T "REG_DWORD" /D "5" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\PackageState" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\PackageState" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableSettingSync"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableSettingSync" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableSettingSyncUserOverride"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableSettingSyncUserOverride" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableAppSyncSettingSync"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableAppSyncSettingSync" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableAppSyncSettingSyncUserOverride"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableAppSyncSettingSyncUserOverride" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableApplicationSettingSync"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableApplicationSettingSync" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableApplicationSettingSyncUserOverride"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableApplicationSettingSyncUserOverride" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableCredentialsSettingSync"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableCredentialsSettingSync" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableCredentialsSettingSyncUserOverride"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableCredentialsSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableDesktopThemeSettingSync"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableDesktopThemeSettingSync" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableDesktopThemeSettingSyncUserOverride"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableDesktopThemeSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisablePersonalizationSettingSync"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisablePersonalizationSettingSync" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisablePersonalizationSettingSyncUserOverride"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisablePersonalizationSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableStartLayoutSettingSync"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableStartLayoutSettingSync" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableStartLayoutSettingSyncUserOverride"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableStartLayoutSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableSyncOnPaidNetwork"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableSyncOnPaidNetwork" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableWebBrowserSettingSync"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableWebBrowserSettingSync" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableWebBrowserSettingSyncUserOverride"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableWebBrowserSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableWindowsSettingSync"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableWindowsSettingSync" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableWindowsSettingSyncUserOverride"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableWindowsSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /V "SyncPolicy"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /V "SyncPolicy" /T "REG_DWORD" /D "5" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\PackageState" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\PackageState" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableSettingSync"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableSettingSync" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableSettingSyncUserOverride"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableSettingSyncUserOverride" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableAppSyncSettingSync"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableAppSyncSettingSync" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableAppSyncSettingSyncUserOverride"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableAppSyncSettingSyncUserOverride" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableApplicationSettingSync"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableApplicationSettingSync" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableApplicationSettingSyncUserOverride"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableApplicationSettingSyncUserOverride" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableCredentialsSettingSync"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableCredentialsSettingSync" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableCredentialsSettingSyncUserOverride"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableCredentialsSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableDesktopThemeSettingSync"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableDesktopThemeSettingSync" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableDesktopThemeSettingSyncUserOverride"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableDesktopThemeSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisablePersonalizationSettingSync"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisablePersonalizationSettingSync" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisablePersonalizationSettingSyncUserOverride"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisablePersonalizationSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableStartLayoutSettingSync"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableStartLayoutSettingSync" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableStartLayoutSettingSyncUserOverride"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableStartLayoutSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableSyncOnPaidNetwork"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableSyncOnPaidNetwork" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableWebBrowserSettingSync"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableWebBrowserSettingSync" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableWebBrowserSettingSyncUserOverride"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableWebBrowserSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableWindowsSettingSync"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableWindowsSettingSync" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableWindowsSettingSyncUserOverride"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableWindowsSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F
)


ECHO .
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Handwriting, inking and contacts :::::
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO .

REG Query "HKLM\Software\Policies\Microsoft\InputPersonalization" /V "RestrictImplicitInkCollection"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Policies\Microsoft\InputPersonalization" /V "RestrictImplicitInkCollection" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /V "RestrictImplicitInkCollection"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /V "RestrictImplicitInkCollection" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /V "PreventHandwritingErrorReports"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /V "PreventHandwritingErrorReports" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\Software\Policies\Microsoft\Windows\TabletPC" /V "PreventHandwritingDataSharing"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Policies\Microsoft\Windows\TabletPC" /V "PreventHandwritingDataSharing" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /V "PreventHandwritingDataSharing"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /V "PreventHandwritingDataSharing" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /V "AllowInputPersonalization"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /V "AllowInputPersonalization" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /V "HarvestContacts"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /V "HarvestContacts" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Policies\Microsoft\InputPersonalization" /V "RestrictImplicitInkCollection"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Policies\Microsoft\InputPersonalization" /V "RestrictImplicitInkCollection" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization" /V "RestrictImplicitInkCollection"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization" /V "RestrictImplicitInkCollection" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /V "PreventHandwritingErrorReports"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /V "PreventHandwritingErrorReports" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\Software\Policies\Microsoft\Windows\TabletPC" /V "PreventHandwritingDataSharing"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Policies\Microsoft\Windows\TabletPC" /V "PreventHandwritingDataSharing" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /V "PreventHandwritingDataSharing"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /V "PreventHandwritingDataSharing" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization" /V "AllowInputPersonalization"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization" /V "AllowInputPersonalization" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /V "HarvestContacts"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /V "HarvestContacts" /T "REG_DWORD" /D "0" /F
)


ECHO .
ECHO :::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling app launch tracking :::::
ECHO :::::::::::::::::::::::::::::::::::::::::
ECHO .


REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "Start_TrackProgs"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "Start_TrackProgs" /D "0" /T "REG_DWORD" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "Start_TrackProgs"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "Start_TrackProgs" /D "0" /T "REG_DWORD" /F
)


ECHO .
ECHO :::::::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling diagnostics and privacy :::::
ECHO :::::::::::::::::::::::::::::::::::::::::::::
ECHO .

REG Query "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /V "DiagnosticErrorText"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /V "DiagnosticErrorText" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /V "DiagnosticErrorText"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /V "DiagnosticErrorText" /T "REG_SZ" /D "" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /V "DiagnosticLinkText"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /V "DiagnosticLinkText" /T "REG_SZ" /D "" /F
)

REG Query "HKLM\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /V "EnabledV9"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /V "EnabledV9" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /V "DisableInventory"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /V "DisableInventory" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /V "DisableUAR"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /V "DisableUAR" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /V "NoLockScreenCamera"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /V "NoLockScreenCamera" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Input\TIPC" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Input\TIPC" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /V "DiagnosticErrorText"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /V "DiagnosticErrorText" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /V "DiagnosticErrorText"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /V "DiagnosticErrorText" /T "REG_SZ" /D "" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /V "DiagnosticLinkText"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /V "DiagnosticLinkText" /T "REG_SZ" /D "" /F
)

REG Query "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /V "EnabledV9"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /V "EnabledV9" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /V "DisableInventory"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /V "DisableInventory" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /V "DisableUAR"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /V "DisableUAR" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Personalization" /V "NoLockScreenCamera"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Personalization" /V "NoLockScreenCamera" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Input\TIPC" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Input\TIPC" /V "Enabled" /T "REG_DWORD" /D "0" /F
)


ECHO .
ECHO :::::::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling windows insider experiments :::::
ECHO :::::::::::::::::::::::::::::::::::::::::::::
ECHO .

REG Query "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" /V "AllowExperimentation"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" /V "AllowExperimentation" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" /V "value"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" /V "value" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\PolicyManager\current\device\System" /V "AllowExperimentation"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\PolicyManager\current\device\System" /V "AllowExperimentation" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" /V "value"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" /V "value" /T "REG_DWORD" /D "0" /F
)


ECHO .
ECHO ::::::::::::::::::::::::::::::::
ECHO ::::: Changing Apps Access :::::
ECHO ::::::::::::::::::::::::::::::::
ECHO .

:::::::::::::::::
ECHO account info
:::::::::::::::::

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /V "Value"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /V "Value" /T "REG_SZ" /D "Deny" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /V "Value"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /V "Value" /T "REG_SZ" /D "Deny" /F
)

:::::::::::
ECHO radios
:::::::::::

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /V "Value"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /V "Value" /T "REG_SZ" /D "Deny" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /V "Value"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /V "Value" /T "REG_SZ" /D "Deny" /F
)

:::::::::::::::
ECHO diagnostic
:::::::::::::::

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" /V "Value"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" /V "Value" /T "REG_SZ" /D "Deny" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" /V "Value"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" /V "Value" /T "REG_SZ" /D "Deny" /F
)

:::::::::::::
ECHO contacts
:::::::::::::

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" /V "Value"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" /V "Value" /T "REG_SZ" /D "Deny" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" /V "Value"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" /V "Value" /T "REG_SZ" /D "Deny" /F
)

:::::::::::::
ECHO calendar
:::::::::::::

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /V "Value"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /V "Value" /T "REG_SZ" /D "Deny" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /V "Value"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /V "Value" /T "REG_SZ" /D "Deny" /F
)

:::::::::::::::::
ECHO call history
:::::::::::::::::

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" /V "Value"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" /V "Value" /T "REG_SZ" /D "Deny" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" /V "Value"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" /V "Value" /T "REG_SZ" /D "Deny" /F
)

::::::::::
ECHO email
::::::::::

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" /V "Value"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" /V "Value" /T "REG_SZ" /D "Deny" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" /V "Value"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" /V "Value" /T "REG_SZ" /D "Deny" /F
)

::::::::::
ECHO tasks
::::::::::

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E390DF20-07DF-446D-B962-F5C953072741}" /V "Value"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E390DF20-07DF-446D-B962-F5C953072741}" /V "Value" /T "REG_SZ" /D "Deny" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E390DF20-07DF-446D-B962-F5C953072741}" /V "Value"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E390DF20-07DF-446D-B962-F5C953072741}" /V "Value" /T "REG_SZ" /D "Deny" /F
)

::::::::::::::::::::::::::::::
ECHO location device hardening
::::::::::::::::::::::::::::::

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /V "GlobalUserDisabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /V "GlobalUserDisabled" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /V "DisableOnline"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /V "DisableOnline" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Browser" /V "AllowAddressBarDropdown"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Browser" /V "AllowAddressBarDropdown" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Privacy" /V "EnableEncryptedMediaExtensions"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Privacy" /V "EnableEncryptedMediaExtensions" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\SettingSync" /V "SyncPolicy"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\SettingSync" /V "SyncPolicy" /T "REG_DWORD" /D "5" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /V "Enabled" /T "REG_DWORD" /D "0" /F)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /V "ModelDownloadAllowed"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /V "ModelDownloadAllowed" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /V "DoNotShowFeedbackNotifications"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /V "DoNotShowFeedbackNotifications" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /V "MaxTelemetryAllowed"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /V "MaxTelemetryAllowed" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Speech" /V "AllowSpeechModelUpdate"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Speech" /V "AllowSpeechModelUpdate" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /V "DisableSettingSync"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /V "DisableSettingSync" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /V "DisableSettingSyncUserOverride"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /V "DisableSettingSyncUserOverride" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SpyNetReporting"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SpyNetReporting" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SubmitSamplesConsent"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SubmitSamplesConsent" /T "REG_DWORD" /D "2" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\MRT" /V "DontReportInfectionInformation"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /V "DontReportInfectionInformation" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\MRT" /V "DontOfferThroughWUAU"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /V "DontOfferThroughWUAU" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /V "DisableAntiSpyware"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /V "DisableAntiSpyware" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SilentInstalledAppsEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SilentInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SoftLandingEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SoftLandingEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\Windows\ScheduledDiagnostics" /V "EnabledExecution"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\Windows\ScheduledDiagnostics" /V "EnabledExecution" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\OneDrive" /V "PreventNetworkTrafficPreUserSignIn"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\OneDrive" /V "PreventNetworkTrafficPreUserSignIn" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Experience" /V "AllowCortana"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Experience" /V "AllowCortana" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Experience" /V "AllowTailoredExperiencesWithDiagnosticData"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Experience" /V "AllowTailoredExperiencesWithDiagnosticData" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /V "Start" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /V "Start" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /V "EnableVirtualizationBasedSecurity"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /V "EnableVirtualizationBasedSecurity" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /V "HVCIMATRequired"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /V "HVCIMATRequired" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /V "GlobalUserDisabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /V "GlobalUserDisabled" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\WMDRM" /V "DisableOnline"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\WMDRM" /V "DisableOnline" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\PolicyManager\current\device\Browser" /V "AllowAddressBarDropdown"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\PolicyManager\current\device\Browser" /V "AllowAddressBarDropdown" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Privacy" /V "EnableEncryptedMediaExtensions"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Privacy" /V "EnableEncryptedMediaExtensions" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync" /V "SyncPolicy"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync" /V "SyncPolicy" /T "REG_DWORD" /D "5" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /V "Enabled" /T "REG_DWORD" /D "0" /F)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /V "Enabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /V "Enabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /V "ModelDownloadAllowed"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /V "ModelDownloadAllowed" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /V "DoNotShowFeedbackNotifications"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /V "DoNotShowFeedbackNotifications" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /V "MaxTelemetryAllowed"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /V "MaxTelemetryAllowed" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Speech" /V "AllowSpeechModelUpdate"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Speech" /V "AllowSpeechModelUpdate" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Policies\Microsoft\Windows\SettingSync" /V "DisableSettingSync"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Policies\Microsoft\Windows\SettingSync" /V "DisableSettingSync" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\Software\Policies\Microsoft\Windows\SettingSync" /V "DisableSettingSyncUserOverride"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Policies\Microsoft\Windows\SettingSync" /V "DisableSettingSyncUserOverride" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SpyNetReporting"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SpyNetReporting" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SubmitSamplesConsent"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /V "SubmitSamplesConsent" /T "REG_DWORD" /D "2" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\MRT" /V "DontReportInfectionInformation"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\MRT" /V "DontReportInfectionInformation" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\MRT" /V "DontOfferThroughWUAU"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\MRT" /V "DontOfferThroughWUAU" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender" /V "DisableAntiSpyware"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender" /V "DisableAntiSpyware" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SilentInstalledAppsEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SilentInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SoftLandingEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SoftLandingEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\Windows\ScheduledDiagnostics" /V "EnabledExecution"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\Windows\ScheduledDiagnostics" /V "EnabledExecution" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\OneDrive" /V "PreventNetworkTrafficPreUserSignIn"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\OneDrive" /V "PreventNetworkTrafficPreUserSignIn" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\PolicyManager\current\device\Experience" /V "AllowCortana"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\PolicyManager\current\device\Experience" /V "AllowCortana" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Microsoft\PolicyManager\current\device\Experience" /V "AllowTailoredExperiencesWithDiagnosticData"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Microsoft\PolicyManager\current\device\Experience" /V "AllowTailoredExperiencesWithDiagnosticData" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /V "Start" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /V "Start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /V "Start" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /V "EnableVirtualizationBasedSecurity"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /V "EnableVirtualizationBasedSecurity" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /V "HVCIMATRequired"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /V "HVCIMATRequired" /T "REG_DWORD" /D "0" /F
)


ECHO .
ECHO :::::::::::::::::::::::::
ECHO ::::: Edge Settings :::::
ECHO :::::::::::::::::::::::::
ECHO .

REG Query "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" /V "CreateDesktopShortcutDefault"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" /V "CreateDesktopShortcutDefault" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "PersonalizationReportingEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "PersonalizationReportingEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "ShowRecommendationsEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "ShowRecommendationsEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "HideFirstRunExperience"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "HideFirstRunExperience" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "UserFeedbackAllowed"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "UserFeedbackAllowed" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "ConfigureDoNotTrack"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "ConfigureDoNotTrack" /T "REG_DWORD" /D "1" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "AlternateErrorPagesEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "AlternateErrorPagesEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "EdgeCollectionsEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "EdgeCollectionsEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "EdgeShoppingAssistantEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "EdgeShoppingAssistantEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "MicrosoftEdgeInsiderPromotionEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "MicrosoftEdgeInsiderPromotionEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "ShowMicrosoftRewards"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "ShowMicrosoftRewards" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "WebWidgetAllowed"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "WebWidgetAllowed" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "DiagnosticData"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "DiagnosticData" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "EdgeAssetDeliveryServiceEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "EdgeAssetDeliveryServiceEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "CryptoWalletEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "CryptoWalletEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "WalletDonationEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "WalletDonationEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\EdgeUpdate" /V "CreateDesktopShortcutDefault"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\EdgeUpdate" /V "CreateDesktopShortcutDefault" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "PersonalizationReportingEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "PersonalizationReportingEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "ShowRecommendationsEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "ShowRecommendationsEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "HideFirstRunExperience"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "HideFirstRunExperience" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "UserFeedbackAllowed"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "UserFeedbackAllowed" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "ConfigureDoNotTrack"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "ConfigureDoNotTrack" /T "REG_DWORD" /D "1" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "AlternateErrorPagesEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "AlternateErrorPagesEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "EdgeCollectionsEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "EdgeCollectionsEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "EdgeShoppingAssistantEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "EdgeShoppingAssistantEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "MicrosoftEdgeInsiderPromotionEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "MicrosoftEdgeInsiderPromotionEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "ShowMicrosoftRewards"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "ShowMicrosoftRewards" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "WebWidgetAllowed"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "WebWidgetAllowed" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "DiagnosticData"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "DiagnosticData" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "EdgeAssetDeliveryServiceEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "EdgeAssetDeliveryServiceEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "CryptoWalletEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "CryptoWalletEnabled" /T "REG_DWORD" /D "0" /F
)

REG Query "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "WalletDonationEnabled"
if %ERRORLEVEL% EQU 0 (
REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "WalletDonationEnabled" /T "REG_DWORD" /D "0" /F
)


ECHO .
ECHO ::::::::::::::::::::::::::::
ECHO ::::: Setting Services :::::
ECHO ::::::::::::::::::::::::::::
ECHO .

ECHO Disabled services
SC Config "AJRouter" Start=Disabled
SC Config "AJRouter_*" Start=Disabled
SC Config "AppVClient" Start=Disabled
SC Config "AppVClient_*" Start=Disabled
SC Config "BcastDVRUserService" Start=Disabled
SC Config "BcastDVRUserService_*" Start=Disabled
SC Config "DialogBlockingService" Start=Disabled
SC Config "DialogBlockingService_*" Start=Disabled
SC Config "Fax" Start=Disabled
SC Config "Fax_*" Start=Disabled
SC Config "MDCoreSvc" Start=Disabled
SC Config "MDCoreSvc_*" Start=Disabled
SC Config "MixedRealityOpenXRSvc" Start=Disabled
SC Config "MixedRealityOpenXRSvc_*" Start=Disabled
SC Config "MsKeyboardFilter" Start=Disabled
SC Config "MsKeyboardFilter_*" Start=Disabled
SC Config "NetTcpPortSharing" Start=Disabled
SC Config "NetTcpPortSharing_*" Start=Disabled
SC Config "OneSyncSvc" Start=Disabled
SC Config "OneSyncSvc_*" Start=Disabled
SC Config "P9RdrService" Start=Disabled
SC Config "P9RdrService_*" Start=Disabled
SC Config "RemoteAccess" Start=Disabled
SC Config "RemoteAccess_*" Start=Disabled
SC Config "RemoteRegistry" Start=Disabled
SC Config "RemoteRegistry_*" Start=Disabled
SC Config "SecurityHealthService" Start=Disabled
SC Config "SecurityHealthService_*" Start=Disabled
SC Config "Sense" Start=Disabled
SC Config "Sense_*" Start=Disabled
SC Config "SensorDataService" Start=Disabled
SC Config "SensorDataService_*" Start=Disabled
SC Config "SysMain" Start=Disabled
SC Config "SysMain_*" Start=Disabled
SC Config "UevAgentService" Start=Disabled
SC Config "UevAgentService_*" Start=Disabled
SC Config "WMPNetworkSvc" Start=Disabled
SC Config "WMPNetworkSvc_*" Start=Disabled
SC Config "WerSvc" Start=Disabled
SC Config "WerSvc_*" Start=Disabled
SC Config "WinDefend" Start=Disabled
SC Config "WinDefend_*" Start=Disabled
SC Config "XblAuthManager" Start=Disabled
SC Config "XblAuthManager_*" Start=Disabled
SC Config "XblGameSave" Start=Disabled
SC Config "XblGameSave_*" Start=Disabled
SC Config "XboxGipSvc" Start=Disabled
SC Config "XboxGipSvc_*" Start=Disabled
SC Config "XboxNetApiSvc" Start=Disabled
SC Config "XboxNetApiSvc_*" Start=Disabled
SC Config "mpssvc" Start=Disabled
SC Config "mpssvc_*" Start=Disabled
SC Config "shpamsvc" Start=Disabled
SC Config "shpamsvc_*" Start=Disabled
SC Config "ssh-agent" Start=Disabled
SC Config "ssh-agent_*" Start=Disabled
SC Config "tzautoupdate" Start=Disabled
SC Config "tzautoupdate_*" Start=Disabled
SC Config "webthreatdefsvc" Start=Disabled
SC Config "webthreatdefsvc_*" Start=Disabled
SC Config "webthreatdefusersvc" Start=Disabled
SC Config "webthreatdefusersvc_*" Start=Disabled
SC Config "workfolderssvc" Start=Disabled
SC Config "workfolderssvc_*" Start=Disabled
SC Config "wsearch" Start=Disabled
SC Config "wsearch_*" Start=Disabled

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AJRouter" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AJRouter" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AppVClient" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AppVClient" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\BcastDVRUserService" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\BcastDVRUserService" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DialogBlockingService" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DialogBlockingService" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Fax" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Fax" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\MDCoreSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MDCoreSvc" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\MixedRealityOpenXRSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MixedRealityOpenXRSvc" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\MsKeyboardFilter" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MsKeyboardFilter" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\OneSyncSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\OneSyncSvc" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\P9RdrService" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\P9RdrService" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SensorDataService" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SensorDataService" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SysMain" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SysMain" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\UevAgentService" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UevAgentService" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WerSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WerSvc" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\XboxGipSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\XboxGipSvc" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\mpssvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\mpssvc" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\shpamsvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\shpamsvc" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\ssh-agent" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ssh-agent" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\tzautoupdate" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\tzautoupdate" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\webthreatdefsvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\webthreatdefsvc" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\webthreatdefusersvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\webthreatdefusersvc" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\workfolderssvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\workfolderssvc" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wsearch" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wsearch" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AJRouter_*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AJRouter_*" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AppVClient_*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AppVClient_*" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\BcastDVRUserService_*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\BcastDVRUserService_*" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DialogBlockingService_*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DialogBlockingService_*" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Fax_*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Fax_*" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\MDCoreSvc_*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MDCoreSvc_*" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\MixedRealityOpenXRSvc_*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MixedRealityOpenXRSvc_*" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\MsKeyboardFilter_*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MsKeyboardFilter_*" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing_*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing_*" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\OneSyncSvc_*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\OneSyncSvc_*" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\P9RdrService_*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\P9RdrService_*" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess_*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess_*" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry_*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry_*" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService_*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService_*" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Sense_*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Sense_*" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SensorDataService_*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SensorDataService_*" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SysMain_*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SysMain_*" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\UevAgentService_*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UevAgentService_*" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc_*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc_*" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WerSvc_*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WerSvc_*" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend_*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend_*" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager_*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager_*" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave_*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave_*" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\XboxGipSvc_*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\XboxGipSvc_*" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc_*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc_*" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\mpssvc_*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\mpssvc_*" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\shpamsvc_*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\shpamsvc_*" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\ssh-agent_*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ssh-agent_*" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\tzautoupdate_*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\tzautoupdate_*" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\webthreatdefsvc_*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\webthreatdefsvc_*" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\webthreatdefusersvc_*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\webthreatdefusersvc_*" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\workfolderssvc_*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\workfolderssvc_*" /V "start" /T "REG_DWORD" /D "4" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wsearch_*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wsearch_*" /V "start" /T "REG_DWORD" /D "4" /F
)

ECHO.

ECHO Manual Services
SC Config "ALG" Start=Demand
SC Config "ALG_*" Start=Demand
SC Config "AarSvc" Start=Demand
SC Config "AarSvc_*" Start=Demand
SC Config "AppIDSvc" Start=Demand
SC Config "AppIDSvc_*" Start=Demand
SC Config "AppMgmt" Start=Demand
SC Config "AppMgmt_*" Start=Demand
SC Config "AppReadiness" Start=Demand
SC Config "AppReadiness_*" Start=Demand
SC Config "AppXSvc" Start=Demand
SC Config "AppXSvc_*" Start=Demand
SC Config "Appinfo" Start=Demand
SC Config "Appinfo_*" Start=Demand
SC Config "ApxSvc" Start=Demand
SC Config "ApxSvc_*" Start=Demand
SC Config "AssignedAccessManagerSvc" Start=Demand
SC Config "AssignedAccessManagerSvc_*" Start=Demand
SC Config "AxInstSV" Start=Demand
SC Config "AxInstSV_*" Start=Demand
SC Config "BDESVC" Start=Demand
SC Config "BDESVC_*" Start=Demand
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
SC Config "CDPSvc" Start=Demand
SC Config "CDPSvc_*" Start=Demand
SC Config "CDPUserSvc" Start=Demand
SC Config "CDPUserSvc_*" Start=Demand
SC Config "COMSysApp" Start=Demand
SC Config "COMSysApp_*" Start=Demand
SC Config "CaptureService" Start=Demand
SC Config "CaptureService_*" Start=Demand
SC Config "CertPropSvc" Start=Demand
SC Config "CertPropSvc_*" Start=Demand
SC Config "ClipSVC" Start=Demand
SC Config "ClipSVC_*" Start=Demand
SC Config "CloudBackupRestoreSvc" Start=Demand
SC Config "CloudBackupRestoreSvc_*" Start=Demand
SC Config "ConsentUxUserSvc" Start=Demand
SC Config "ConsentUxUserSvc_*" Start=Demand
SC Config "CredentialEnrollmentManagerUserSvc" Start=Demand
SC Config "CredentialEnrollmentManagerUserSvc_*" Start=Demand
SC Config "CscService" Start=Demand
SC Config "CscService_*" Start=Demand
SC Config "DPS" Start=Demand
SC Config "DPS_*" Start=Demand
SC Config "DcpSvc" Start=Demand
SC Config "DcpSvc_*" Start=Demand
SC Config "DevQueryBroker" Start=Demand
SC Config "DevQueryBroker_*" Start=Demand
SC Config "DeviceAssociationBrokerSvc" Start=Demand
SC Config "DeviceAssociationBrokerSvc_*" Start=Demand
SC Config "DeviceAssociationService" Start=Demand
SC Config "DeviceAssociationService_*" Start=Demand
SC Config "DeviceInstall" Start=Demand
SC Config "DeviceInstall_*" Start=Demand
SC Config "DevicePickerUserSvc" Start=Demand
SC Config "DevicePickerUserSvc_*" Start=Demand
SC Config "DevicesFlowUserSvc" Start=Demand
SC Config "DevicesFlowUserSvc_*" Start=Demand
SC Config "DiagTrack" Start=Demand
SC Config "DiagTrack_*" Start=Demand
SC Config "DisplayEnhancementService" Start=Demand
SC Config "DisplayEnhancementService_*" Start=Demand
SC Config "DmEnrollmentSvc" Start=Demand
SC Config "DmEnrollmentSvc_*" Start=Demand
SC Config "DoSvc" Start=Demand
SC Config "DoSvc_*" Start=Demand
SC Config "DsSvc" Start=Demand
SC Config "DsSvc_*" Start=Demand
SC Config "DsmSvc" Start=Demand
SC Config "DsmSvc_*" Start=Demand
SC Config "DusmSvc" Start=Demand
SC Config "DusmSvc_*" Start=Demand
SC Config "EFS" Start=Demand
SC Config "EFS_*" Start=Demand
SC Config "EapHost" Start=Demand
SC Config "EapHost_*" Start=Demand
SC Config "EntAppSvc" Start=Demand
SC Config "EntAppSvc_*" Start=Demand
SC Config "FDResPub" Start=Demand
SC Config "FDResPub_*" Start=Demand
SC Config "FontCache" Start=Demand
SC Config "FontCache_*" Start=Demand
SC Config "FrameServer" Start=Demand
SC Config "FrameServerMonitor" Start=Demand
SC Config "FrameServerMonitor_*" Start=Demand
SC Config "FrameServer_*" Start=Demand
SC Config "GameInputSvc" Start=Demand
SC Config "GameInputSvc_*" Start=Demand
SC Config "GraphicsPerfSvc" Start=Demand
SC Config "GraphicsPerfSvc_*" Start=Demand
SC Config "HomeGroupListener" Start=Demand
SC Config "HomeGroupListener_*" Start=Demand
SC Config "HomeGroupProvider" Start=Demand
SC Config "HomeGroupProvider_*" Start=Demand
SC Config "HvHost" Start=Demand
SC Config "HvHost_*" Start=Demand
SC Config "IEEtwCollectorService" Start=Demand
SC Config "IEEtwCollectorService_*" Start=Demand
SC Config "InstallService" Start=Demand
SC Config "InstallService_*" Start=Demand
SC Config "InventorySvc" Start=Demand
SC Config "InventorySvc_*" Start=Demand
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
SC Config "MSiSCSI" Start=Demand
SC Config "MSiSCSI_*" Start=Demand
SC Config "MapsBroker" Start=Demand
SC Config "MapsBroker_*" Start=Demand
SC Config "McmSvc" Start=Demand
SC Config "McmSvc_*" Start=Demand
SC Config "McpManagementService" Start=Demand
SC Config "McpManagementService_*" Start=Demand
SC Config "MessagingService" Start=Demand
SC Config "MessagingService_*" Start=Demand
SC Config "MicrosoftEdgeElevationService" Start=Demand
SC Config "MicrosoftEdgeElevationService_*" Start=Demand
SC Config "NPSMSvc" Start=Demand
SC Config "NPSMSvc_*" Start=Demand
SC Config "NaturalAuthentication" Start=Demand
SC Config "NaturalAuthentication_*" Start=Demand
SC Config "NcaSvc" Start=Demand
SC Config "NcaSvc_*" Start=Demand
SC Config "NcbService" Start=Demand
SC Config "NcbService_*" Start=Demand
SC Config "NcdAutoSetup" Start=Demand
SC Config "NcdAutoSetup_*" Start=Demand
SC Config "NetSetupSvc" Start=Demand
SC Config "NetSetupSvc_*" Start=Demand
SC Config "Netlogon" Start=Demand
SC Config "Netlogon_*" Start=Demand
SC Config "Netman" Start=Demand
SC Config "Netman_*" Start=Demand
SC Config "NgcCtnrSvc" Start=Demand
SC Config "NgcCtnrSvc_*" Start=Demand
SC Config "NgcSvc" Start=Demand
SC Config "NgcSvc_*" Start=Demand
SC Config "NlaSvc" Start=Demand
SC Config "NlaSvc_*" Start=Demand
SC Config "PNRPAutoREG" Start=Demand
SC Config "PNRPAutoREG_*" Start=Demand
SC Config "PNRPsvc" Start=Demand
SC Config "PNRPsvc_*" Start=Demand
SC Config "PcaSvc" Start=Demand
SC Config "PcaSvc_*" Start=Demand
SC Config "PeerDistSvc" Start=Demand
SC Config "PeerDistSvc_*" Start=Demand
SC Config "PenService" Start=Demand
SC Config "PenService_*" Start=Demand
SC Config "PerfHost" Start=Demand
SC Config "PerfHost_*" Start=Demand
SC Config "PhoneSvc" Start=Demand
SC Config "PhoneSvc_*" Start=Demand
SC Config "PimIndexMaintenanceSvc" Start=Demand
SC Config "PimIndexMaintenanceSvc_*" Start=Demand
SC Config "PlugPlay" Start=Demand
SC Config "PlugPlay_*" Start=Demand
SC Config "PolicyAgent" Start=Demand
SC Config "PolicyAgent_*" Start=Demand
SC Config "PrintDeviceConfigurationService" Start=Demand
SC Config "PrintDeviceConfigurationService_*" Start=Demand
SC Config "PrintNotify" Start=Demand
SC Config "PrintNotify_*" Start=Demand
SC Config "PrintScanBrokerService" Start=Demand
SC Config "PrintScanBrokerService_*" Start=Demand
SC Config "PrintWorkflowUserSvc" Start=Demand
SC Config "PrintWorkflowUserSvc_*" Start=Demand
SC Config "PushToInstall" Start=Demand
SC Config "PushToInstall_*" Start=Demand
SC Config "QWAVE" Start=Demand
SC Config "QWAVE_*" Start=Demand
SC Config "RasAuto" Start=Demand
SC Config "RasAuto_*" Start=Demand
SC Config "RasMan" Start=Demand
SC Config "RasMan_*" Start=Demand
SC Config "RetailDemo" Start=Demand
SC Config "RetailDemo_*" Start=Demand
SC Config "RmSvc" Start=Demand
SC Config "RmSvc_*" Start=Demand
SC Config "RpcLocator" Start=Demand
SC Config "RpcLocator_*" Start=Demand
SC Config "SCPolicySvc" Start=Demand
SC Config "SCPolicySvc_*" Start=Demand
SC Config "SCardSvr" Start=Demand
SC Config "SCardSvr_*" Start=Demand
SC Config "SDRSVC" Start=Demand
SC Config "SDRSVC_*" Start=Demand
SC Config "SEMgrSvc" Start=Demand
SC Config "SEMgrSvc_*" Start=Demand
SC Config "SNMPTRAP" Start=Demand
SC Config "SNMPTRAP_*" Start=Demand
SC Config "SSDPSRV" Start=Demand
SC Config "SSDPSRV_*" Start=Demand
SC Config "ScDeviceEnum" Start=Demand
SC Config "ScDeviceEnum_*" Start=Demand
SC Config "SensorService" Start=Demand
SC Config "SensorService_*" Start=Demand
SC Config "SensrSvc" Start=Demand
SC Config "SensrSvc_*" Start=Demand
SC Config "SessionEnv" Start=Demand
SC Config "SessionEnv_*" Start=Demand
SC Config "SharedAccess" Start=Demand
SC Config "SharedAccess_*" Start=Demand
SC Config "SharedRealitySvc" Start=Demand
SC Config "SharedRealitySvc_*" Start=Demand
SC Config "ShellHWDetection" Start=Demand
SC Config "ShellHWDetection_*" Start=Demand
SC Config "SmsRouter" Start=Demand
SC Config "SmsRouter_*" Start=Demand
SC Config "Spooler" Start=Demand
SC Config "Spooler_*" Start=Demand
SC Config "SstpSvc" Start=Demand
SC Config "SstpSvc_*" Start=Demand
SC Config "StiSvc" Start=Demand
SC Config "StiSvc_*" Start=Demand
SC Config "StorSvc" Start=Demand
SC Config "StorSvc_*" Start=Demand
SC Config "TabletInputService" Start=Demand
SC Config "TabletInputService_*" Start=Demand
SC Config "TapiSrv" Start=Demand
SC Config "TapiSrv_*" Start=Demand
SC Config "TermService" Start=Demand
SC Config "TermService_*" Start=Demand
SC Config "Themes" Start=Demand
SC Config "Themes_*" Start=Demand
SC Config "TieringEngineService" Start=Demand
SC Config "TieringEngineService_*" Start=Demand
SC Config "TimeBroker" Start=Demand
SC Config "TimeBrokerSvc" Start=Demand
SC Config "TimeBrokerSvc_*" Start=Demand
SC Config "TimeBroker_*" Start=Demand
SC Config "TokenBroker" Start=Demand
SC Config "TokenBroker_*" Start=Demand
SC Config "TroubleshootingSvc" Start=Demand
SC Config "TroubleshootingSvc_*" Start=Demand
SC Config "UI0Detect" Start=Demand
SC Config "UI0Detect_*" Start=Demand
SC Config "UdkUserSvc" Start=Demand
SC Config "UdkUserSvc_*" Start=Demand
SC Config "UmRdpService" Start=Demand
SC Config "UmRdpService_*" Start=Demand
SC Config "UnistoreSvc" Start=Demand
SC Config "UnistoreSvc_*" Start=Demand
SC Config "UserDataSvc" Start=Demand
SC Config "UserDataSvc_*" Start=Demand
SC Config "UsoSvc" Start=Demand
SC Config "UsoSvc_*" Start=Demand
SC Config "VSS" Start=Demand
SC Config "VSS_*" Start=Demand
SC Config "VacSvc" Start=Demand
SC Config "VacSvc_*" Start=Demand
SC Config "VaultSvc" Start=Demand
SC Config "VaultSvc_*" Start=Demand
SC Config "W32Time" Start=Demand
SC Config "W32Time_*" Start=Demand
SC Config "WEPHOSTSVC" Start=Demand
SC Config "WEPHOSTSVC_*" Start=Demand
SC Config "WFDSConMgrSvc" Start=Demand
SC Config "WFDSConMgrSvc_*" Start=Demand
SC Config "WManSvc" Start=Demand
SC Config "WManSvc_*" Start=Demand
SC Config "WPDBusEnum" Start=Demand
SC Config "WPDBusEnum_*" Start=Demand
SC Config "WSService" Start=Demand
SC Config "WSService_*" Start=Demand
SC Config "WaaSMedicSvc" Start=Demand
SC Config "WaaSMedicSvc_*" Start=Demand
SC Config "WalletService" Start=Demand
SC Config "WalletService_*" Start=Demand
SC Config "WarpJITSvc" Start=Demand
SC Config "WarpJITSvc_*" Start=Demand
SC Config "WbioSrvc" Start=Demand
SC Config "WbioSrvc_*" Start=Demand
SC Config "WcsPlugInService" Start=Demand
SC Config "WcsPlugInService_*" Start=Demand
SC Config "WdNisSvc" Start=Demand
SC Config "WdNisSvc_*" Start=Demand
SC Config "WdiServiceHost" Start=Demand
SC Config "WdiServiceHost_*" Start=Demand
SC Config "WdiSystemHost" Start=Demand
SC Config "WdiSystemHost_*" Start=Demand
SC Config "WebClient" Start=Demand
SC Config "WebClient_*" Start=Demand
SC Config "Wecsvc" Start=Demand
SC Config "Wecsvc_*" Start=Demand
SC Config "WiaRpc" Start=Demand
SC Config "WiaRpc_*" Start=Demand
SC Config "WinHttpAutoProxySvc" Start=Demand
SC Config "WinHttpAutoProxySvc_*" Start=Demand
SC Config "WinRM" Start=Demand
SC Config "WinRM_*" Start=Demand
SC Config "WlanSvc" Start=Demand
SC Config "WlanSvc_*" Start=Demand
SC Config "WpcMonSvc" Start=Demand
SC Config "WpcMonSvc_*" Start=Demand
SC Config "WpnService" Start=Demand
SC Config "WpnService_*" Start=Demand
SC Config "WwanSvc" Start=Demand
SC Config "WwanSvc_*" Start=Demand
SC Config "ZTHELPER" Start=Demand
SC Config "ZTHELPER_*" Start=Demand
SC Config "autotimesvc" Start=Demand
SC Config "autotimesvc_*" Start=Demand
SC Config "bthserv" Start=Demand
SC Config "bthserv_*" Start=Demand
SC Config "camsvc" Start=Demand
SC Config "camsvc_*" Start=Demand
SC Config "cbdhsvc" Start=Demand
SC Config "cbdhsvc_*" Start=Demand
SC Config "cloudidsvc" Start=Demand
SC Config "cloudidsvc_*" Start=Demand
SC Config "dcsvc" Start=Demand
SC Config "dcsvc_*" Start=Demand
SC Config "defragsvc" Start=Demand
SC Config "defragsvc_*" Start=Demand
SC Config "diagnosticshub.standardcollector.service" Start=Demand
SC Config "diagnosticshub.standardcollector.service_*" Start=Demand
SC Config "diagsvc" Start=Demand
SC Config "diagsvc_*" Start=Demand
SC Config "dmwappushservice" Start=Demand
SC Config "dmwappushservice_*" Start=Demand
SC Config "dot3svc" Start=Demand
SC Config "dot3svc_*" Start=Demand
SC Config "edgeupdate" Start=Demand
SC Config "edgeupdate_*" Start=Demand
SC Config "edgeupdatem" Start=Demand
SC Config "edgeupdatem_*" Start=Demand
SC Config "embeddedmode" Start=Demand
SC Config "embeddedmode_*" Start=Demand
SC Config "fdPHost" Start=Demand
SC Config "fdPHost_*" Start=Demand
SC Config "fhsvc" Start=Demand
SC Config "fhsvc_*" Start=Demand
SC Config "hidserv" Start=Demand
SC Config "hidserv_*" Start=Demand
SC Config "hpatchmon" Start=Demand
SC Config "hpatchmon_*" Start=Demand
SC Config "icssvc" Start=Demand
SC Config "icssvc_*" Start=Demand
SC Config "lfsvc" Start=Demand
SC Config "lfsvc_*" Start=Demand
SC Config "lltdsvc" Start=Demand
SC Config "lltdsvc_*" Start=Demand
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
SC Config "perceptionsimulation" Start=Demand
SC Config "perceptionsimulation_*" Start=Demand
SC Config "pla" Start=Demand
SC Config "pla_*" Start=Demand
SC Config "refsdedupsvc" Start=Demand
SC Config "refsdedupsvc_*" Start=Demand
SC Config "seclogon" Start=Demand
SC Config "seclogon_*" Start=Demand
SC Config "smphost" Start=Demand
SC Config "smphost_*" Start=Demand
SC Config "spectrum" Start=Demand
SC Config "spectrum_*" Start=Demand
SC Config "svsvc" Start=Demand
SC Config "svsvc_*" Start=Demand
SC Config "swprv" Start=Demand
SC Config "swprv_*" Start=Demand
SC Config "uhssvc" Start=Demand
SC Config "uhssvc_*" Start=Demand
SC Config "upnphost" Start=Demand
SC Config "upnphost_*" Start=Demand
SC Config "vds" Start=Demand
SC Config "vds_*" Start=Demand
SC Config "vm3dservice" Start=Demand
SC Config "vm3dservice_*" Start=Demand
SC Config "vmicguestinterface" Start=Demand
SC Config "vmicguestinterface_*" Start=Demand
SC Config "vmicheartbeat" Start=Demand
SC Config "vmicheartbeat_*" Start=Demand
SC Config "vmickvpexchange" Start=Demand
SC Config "vmickvpexchange_*" Start=Demand
SC Config "vmicrdv" Start=Demand
SC Config "vmicrdv_*" Start=Demand
SC Config "vmicshutdown" Start=Demand
SC Config "vmicshutdown_*" Start=Demand
SC Config "vmictimesync" Start=Demand
SC Config "vmictimesync_*" Start=Demand
SC Config "vmicvmsession" Start=Demand
SC Config "vmicvmsession_*" Start=Demand
SC Config "vmicvss" Start=Demand
SC Config "vmicvss_*" Start=Demand
SC Config "vmvss" Start=Demand
SC Config "vmvss_*" Start=Demand
SC Config "wbengine" Start=Demand
SC Config "wbengine_*" Start=Demand
SC Config "wcncsvc" Start=Demand
SC Config "wcncsvc_*" Start=Demand
SC Config "wercplsupport" Start=Demand
SC Config "wercplsupport_*" Start=Demand
SC Config "whesvc" Start=Demand
SC Config "whesvc_*" Start=Demand
SC Config "wisvc" Start=Demand
SC Config "wisvc_*" Start=Demand
SC Config "wlidsvc" Start=Demand
SC Config "wlidsvc_*" Start=Demand
SC Config "wlpasvc" Start=Demand
SC Config "wlpasvc_*" Start=Demand
SC Config "wmiApSrv" Start=Demand
SC Config "wmiApSrv_*" Start=Demand
SC Config "wscsvc" Start=Demand
SC Config "wscsvc_*" Start=Demand
SC Config "wuauserv" Start=Demand
SC Config "wuauserv_*" Start=Demand
SC Config "wudfsvc" Start=Demand
SC Config "wudfsvc_*" Start=Demand

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\ALG" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ALG" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AarSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AarSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AppIDSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AppIDSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AppMgmt" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AppMgmt" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AppReadiness" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AppReadiness" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AppXSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AppXSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Appinfo" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Appinfo" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\ApxSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ApxSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AssignedAccessManagerSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AssignedAccessManagerSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AxInstSV" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AxInstSV" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\BDESVC" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\BDESVC" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\BITS" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\BITS" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\BTAGService" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\BTAGService" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\BluetoothUserService" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\BluetoothUserService" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Browser" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Browser" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\BthAvctpSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\BthAvctpSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\CDPSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CDPSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\CDPUserSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CDPUserSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\COMSysApp" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\COMSysApp" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\CaptureService" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CaptureService" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\CertPropSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CertPropSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\ClipSVC" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ClipSVC" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\CloudBackupRestoreSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CloudBackupRestoreSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\CscService" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CscService" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DPS" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DPS" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DcpSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DcpSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DevQueryBroker" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DevQueryBroker" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DeviceAssociationService" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DeviceAssociationService" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DeviceInstall" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DeviceInstall" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DisplayEnhancementService" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DisplayEnhancementService" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DmEnrollmentSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DmEnrollmentSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DoSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DoSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DsSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DsSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DsmSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DsmSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DusmSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DusmSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\EFS" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\EFS" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\EapHost" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\EapHost" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\EntAppSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\EntAppSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\FDResPub" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\FDResPub" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\FontCache" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\FontCache" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\FrameServer" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\FrameServer" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\FrameServerMonitor" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\FrameServerMonitor" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\GameInputSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\GameInputSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupListener" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupListener" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupProvider" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupProvider" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\HvHost" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\HvHost" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\IEEtwCollectorService" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\IEEtwCollectorService" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\InstallService" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\InstallService" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\InventorySvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\InventorySvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\IpxlatCfgSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\IpxlatCfgSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\KeyIso" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\KeyIso" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\KtmRm" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\KtmRm" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\LicenseManager" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\LicenseManager" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\LocalKdc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\LocalKdc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\LxpSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\LxpSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\MSDTC" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MSDTC" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\MSiSCSI" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MSiSCSI" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\MapsBroker" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MapsBroker" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\McmSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\McmSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\McpManagementService" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\McpManagementService" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\MessagingService" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MessagingService" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationService" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationService" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NPSMSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NPSMSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NaturalAuthentication" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NaturalAuthentication" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NcaSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NcaSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NcbService" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NcbService" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NcdAutoSetup" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NcdAutoSetup" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NetSetupSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NetSetupSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Netman" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Netman" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NgcCtnrSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NgcCtnrSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NgcSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NgcSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PNRPAutoREG" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PNRPAutoREG" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PNRPsvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PNRPsvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PcaSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PcaSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PeerDistSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PeerDistSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PenService" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PenService" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PerfHost" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PerfHost" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PhoneSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PhoneSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PlugPlay" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PlugPlay" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgent" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgent" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PrintDeviceConfigurationService" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PrintDeviceConfigurationService" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PrintNotify" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PrintNotify" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PrintScanBrokerService" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PrintScanBrokerService" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PushToInstall" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PushToInstall" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\QWAVE" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\QWAVE" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\RasAuto" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RasAuto" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\RasMan" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RasMan" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\RetailDemo" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RetailDemo" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\RmSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RmSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\RpcLocator" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RpcLocator" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SCPolicySvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SCPolicySvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SCardSvr" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SCardSvr" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SDRSVC" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SDRSVC" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SEMgrSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SEMgrSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SNMPTRAP" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SNMPTRAP" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SSDPSRV" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SSDPSRV" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\ScDeviceEnum" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ScDeviceEnum" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SensorService" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SensorService" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SensrSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SensrSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SessionEnv" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SessionEnv" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SharedRealitySvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SharedRealitySvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\ShellHWDetection" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ShellHWDetection" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SmsRouter" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SmsRouter" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SstpSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SstpSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\StiSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\StiSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\StorSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\StorSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\TabletInputService" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TabletInputService" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\TapiSrv" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TapiSrv" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\TermService" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TermService" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Themes" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Themes" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\TieringEngineService" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TieringEngineService" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\TimeBroker" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TimeBroker" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\TokenBroker" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TokenBroker" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\TroubleshootingSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TroubleshootingSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\UI0Detect" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UI0Detect" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\UdkUserSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UdkUserSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\UmRdpService" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UmRdpService" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\UnistoreSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UnistoreSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\UserDataSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UserDataSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\UsoSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UsoSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\VSS" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\VSS" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\VacSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\VacSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\VaultSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\VaultSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\W32Time" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\W32Time" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WEPHOSTSVC" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WEPHOSTSVC" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WFDSConMgrSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WFDSConMgrSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WManSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WManSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WPDBusEnum" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WPDBusEnum" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WSService" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WSService" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WalletService" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WalletService" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WarpJITSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WarpJITSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WbioSrvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WbioSrvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WcsPlugInService" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WcsPlugInService" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WdiServiceHost" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WdiServiceHost" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WdiSystemHost" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WdiSystemHost" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WebClient" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WebClient" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Wecsvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Wecsvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WiaRpc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WinRM" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WinRM" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WlanSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WlanSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WpcMonSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WpcMonSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WpnService" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WpnService" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WwanSvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WwanSvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\ZTHELPER" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ZTHELPER" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\autotimesvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\autotimesvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\bthserv" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\bthserv" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\camsvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\camsvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\cbdhsvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\cbdhsvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\cloudidsvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\cloudidsvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\dcsvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\dcsvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\defragsvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\defragsvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\diagsvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\diagsvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\dot3svc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\dot3svc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdate" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdate" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdatem" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdatem" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\embeddedmode" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\embeddedmode" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\fdPHost" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\fdPHost" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\fhsvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\fhsvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\hidserv" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\hidserv" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\hpatchmon" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\hpatchmon" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\icssvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\icssvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\lltdsvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\lltdsvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\lmhosts" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\lmhosts" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\msiserver" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\msiserver" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\netprofm" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\netprofm" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\p2pimsvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\p2pimsvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\p2psvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\p2psvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\perceptionsimulation" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\perceptionsimulation" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\pla" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\pla" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\refsdedupsvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\refsdedupsvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\seclogon" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\seclogon" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\smphost" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\smphost" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\spectrum" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\spectrum" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\svsvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\svsvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\swprv" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\swprv" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\uhssvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\uhssvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\upnphost" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\upnphost" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vds" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vds" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vm3dservice" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vm3dservice" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmicguestinterface" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmicguestinterface" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmicheartbeat" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmicheartbeat" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmickvpexchange" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmickvpexchange" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmicrdv" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmicrdv" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmicshutdown" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmicshutdown" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmictimesync" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmictimesync" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmicvmsession" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmicvmsession" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmicvss" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmicvss" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmvss" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmvss" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wbengine" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wbengine" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wcncsvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wcncsvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wercplsupport" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wercplsupport" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\whesvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\whesvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wisvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wisvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wlidsvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wlidsvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wlpasvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wlpasvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wmiApSrv" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wmiApSrv" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wscsvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wscsvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wuauserv" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wuauserv" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wudfsvc" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wudfsvc" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\ALGـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ALGـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AarSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AarSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AppIDSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AppIDSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AppMgmtـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AppMgmtـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AppReadinessـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AppReadinessـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AppXSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AppXSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Appinfoـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Appinfoـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\ApxSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ApxSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AssignedAccessManagerSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AssignedAccessManagerSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AxInstSVـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AxInstSVـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\BDESVCـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\BDESVCـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\BITSـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\BITSـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\BTAGServiceـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\BTAGServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\BluetoothUserServiceـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\BluetoothUserServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Browserـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Browserـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\BthAvctpSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\BthAvctpSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\CDPSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CDPSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\CDPUserSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CDPUserSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\COMSysAppـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\COMSysAppـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\CaptureServiceـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CaptureServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\CertPropSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CertPropSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\ClipSVCـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ClipSVCـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\CloudBackupRestoreSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CloudBackupRestoreSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\CscServiceـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CscServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DPSـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DPSـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DcpSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DcpSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DevQueryBrokerـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DevQueryBrokerـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DeviceAssociationServiceـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DeviceAssociationServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DeviceInstallـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DeviceInstallـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrackـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrackـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DisplayEnhancementServiceـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DisplayEnhancementServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DmEnrollmentSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DmEnrollmentSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DoSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DoSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DsSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DsSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DsmSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DsmSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DusmSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DusmSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\EFSـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\EFSـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\EapHostـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\EapHostـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\EntAppSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\EntAppSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\FDResPubـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\FDResPubـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\FontCacheـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\FontCacheـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\FrameServerـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\FrameServerـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\FrameServerMonitorـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\FrameServerMonitorـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\GameInputSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\GameInputSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupListenerـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupListenerـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupProviderـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupProviderـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\HvHostـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\HvHostـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\IEEtwCollectorServiceـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\IEEtwCollectorServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\InstallServiceـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\InstallServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\InventorySvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\InventorySvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\IpxlatCfgSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\IpxlatCfgSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\KeyIsoـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\KeyIsoـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\KtmRmـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\KtmRmـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\LicenseManagerـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\LicenseManagerـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\LocalKdcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\LocalKdcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\LxpSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\LxpSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\MSDTCـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MSDTCـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\MSiSCSIـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MSiSCSIـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\MapsBrokerـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MapsBrokerـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\McmSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\McmSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\McpManagementServiceـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\McpManagementServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\MessagingServiceـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MessagingServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationServiceـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NPSMSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NPSMSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NaturalAuthenticationـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NaturalAuthenticationـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NcaSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NcaSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NcbServiceـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NcbServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NcdAutoSetupـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NcdAutoSetupـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NetSetupSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NetSetupSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Netlogonـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogonـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Netmanـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Netmanـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NgcCtnrSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NgcCtnrSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NgcSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NgcSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PNRPAutoREGـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PNRPAutoREGـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PNRPsvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PNRPsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PcaSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PcaSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PeerDistSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PeerDistSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PenServiceـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PenServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PerfHostـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PerfHostـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PhoneSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PhoneSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PlugPlayـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PlugPlayـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgentـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgentـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PrintDeviceConfigurationServiceـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PrintDeviceConfigurationServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PrintNotifyـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PrintNotifyـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PrintScanBrokerServiceـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PrintScanBrokerServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PushToInstallـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PushToInstallـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\QWAVEـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\QWAVEـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\RasAutoـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RasAutoـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\RasManـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RasManـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\RetailDemoـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RetailDemoـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\RmSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RmSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\RpcLocatorـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RpcLocatorـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SCPolicySvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SCPolicySvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SCardSvrـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SCardSvrـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SDRSVCـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SDRSVCـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SEMgrSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SEMgrSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SNMPTRAPـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SNMPTRAPـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SSDPSRVـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SSDPSRVـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\ScDeviceEnumـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ScDeviceEnumـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SensorServiceـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SensorServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SensrSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SensrSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SessionEnvـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SessionEnvـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccessـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccessـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SharedRealitySvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SharedRealitySvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\ShellHWDetectionـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ShellHWDetectionـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SmsRouterـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SmsRouterـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Spoolerـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Spoolerـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SstpSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SstpSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\StiSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\StiSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\StorSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\StorSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\TabletInputServiceـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TabletInputServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\TapiSrvـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TapiSrvـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\TermServiceـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TermServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Themesـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Themesـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\TieringEngineServiceـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TieringEngineServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\TimeBrokerـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TimeBrokerـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\TimeBrokerSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TimeBrokerSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\TokenBrokerـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TokenBrokerـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\TroubleshootingSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TroubleshootingSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\UI0Detectـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UI0Detectـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\UdkUserSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UdkUserSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\UmRdpServiceـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UmRdpServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\UnistoreSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UnistoreSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\UserDataSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UserDataSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\UsoSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UsoSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\VSSـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\VSSـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\VacSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\VacSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\VaultSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\VaultSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\W32Timeـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\W32Timeـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WEPHOSTSVCـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WEPHOSTSVCـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WFDSConMgrSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WFDSConMgrSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WManSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WManSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WPDBusEnumـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WPDBusEnumـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WSServiceـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WSServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WalletServiceـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WalletServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WarpJITSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WarpJITSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WbioSrvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WbioSrvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WcsPlugInServiceـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WcsPlugInServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WdiServiceHostـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WdiServiceHostـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WdiSystemHostـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WdiSystemHostـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WebClientـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WebClientـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Wecsvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Wecsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WiaRpcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WinRMـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WinRMـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WlanSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WlanSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WpcMonSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WpcMonSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WpnServiceـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WpnServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WwanSvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WwanSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\ZTHELPERـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ZTHELPERـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\autotimesvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\autotimesvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\bthservـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\bthservـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\camsvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\camsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\cbdhsvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\cbdhsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\cloudidsvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\cloudidsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\dcsvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\dcsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\defragsvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\defragsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.serviceـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.serviceـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\diagsvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\diagsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushserviceـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushserviceـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\dot3svcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\dot3svcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdateـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdateـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdatemـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdatemـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\embeddedmodeـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\embeddedmodeـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\fdPHostـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\fdPHostـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\fhsvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\fhsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\hidservـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\hidservـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\hpatchmonـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\hpatchmonـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\icssvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\icssvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\lfsvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\lltdsvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\lltdsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\lmhostsـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\lmhostsـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\msiserverـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\msiserverـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\netprofmـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\netprofmـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\p2pimsvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\p2pimsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\p2psvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\p2psvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\perceptionsimulationـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\perceptionsimulationـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\plaـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\plaـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\refsdedupsvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\refsdedupsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\seclogonـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\seclogonـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\smphostـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\smphostـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\spectrumـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\spectrumـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\svsvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\svsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\swprvـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\swprvـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\uhssvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\uhssvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\upnphostـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\upnphostـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vdsـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vdsـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vm3dserviceـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vm3dserviceـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmicguestinterfaceـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmicguestinterfaceـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmicheartbeatـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmicheartbeatـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmickvpexchangeـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmickvpexchangeـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmicrdvـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmicrdvـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmicshutdownـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmicshutdownـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmictimesyncـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmictimesyncـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmicvmsessionـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmicvmsessionـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmicvssـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmicvssـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmvssـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmvssـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wbengineـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wbengineـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wcncsvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wcncsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wercplsupportـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wercplsupportـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\whesvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\whesvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wisvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wisvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wlidsvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wlidsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wlpasvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wlpasvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wmiApSrvـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wmiApSrvـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wscsvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wscsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wuauservـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wuauservـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wudfsvcـ*" /V "start"
if %ERRORLEVEL% EQU 0 (
REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wudfsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F
)

ECHO .


ECHO .
ECHO :::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Scheduled Tasks :::::
ECHO :::::::::::::::::::::::::::::::::::::
ECHO.

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
SchTasks /Change /TN "Microsoft\Windows\remoteAssistance\remoteAssistanceTask" /Disable
SchTasks /Change /TN "Microsoft\Windows\EnterpriseMgmt\MDMMaintenenceTask" /Disable
SchTasks /Change /TN "Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" /Disable
SchTasks /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuaRD MDM policy Refresh" /Disable
SchTasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable
SchTasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /Disable
SchTasks /Change /TN "Microsoft\Windows\FileHistory/File History (maintenance mode)" /Disable
SchTasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable
SchTasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\ReconcileFeatures" /Disable
SchTasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataFlushing" /Disable
SchTasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataReporting" /Disable
SchTasks /Change /TN "Microsoft\Windows\Flighting\OneSettings\RefreshCache" /Disable
SchTasks /Change /TN "Microsoft\Windows\Input\InputSettingsRestoreDataAvailable" /Disable
SchTasks /Change /TN "Microsoft\Windows\Input\LocalUserSyncDataAvailable" /Disable
SchTasks /Change /TN "Microsoft\Windows\Input\MouseSyncDataAvailable" /Disable
SchTasks /Change /TN "Microsoft\Windows\Input\PenSyncDataAvailable" /Disable
SchTasks /Change /TN "Microsoft\Windows\Input\RemoteMouseSyncDataAvailable" /Disable
SchTasks /Change /TN "Microsoft\Windows\Input\RemotePenSyncDataAvailable" /Disable
SchTasks /Change /TN "Microsoft\Windows\Input\RemoteTouchpadSyncDataAvailable" /Disable
SchTasks /Change /TN "Microsoft\Windows\Input\TouchpadSyncDataAvailable" /Disable
SchTasks /Change /TN "Microsoft\Windows\International\Synchronize Language Settings" /Disable
SchTasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Installation" /Disable
SchTasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources" /Disable
SchTasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Uninstallation" /Disable
SchTasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /Disable
SchTasks /Change /TN "Microsoft\Windows\MUI\LPremove" /Disable
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
SchTasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable
SchTasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable
SchTasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable
SchTasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable
SchTasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
SchTasks /Change /TN "Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" /Disable
SchTasks /Change /TN "Microsoft\Windows\WindowsAI\Settings\InitialConfiguration" /Disable
SchTasks /Change /TN "Microsoft\Windows\WlanSvc\CDSSync" /Disable
SchTasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Logon Synchronization" /Disable
SchTasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Maintenance Work" /Disable
SchTasks /Change /TN "Microsoft\Windows\Workplace Join\Automatic-Device-Join" /Disable
SchTasks /Change /TN "Microsoft\Windows\WwanSvc\NotificationTask" /Disable
SchTasks /Change /TN "Microsoft\Windows\WwanSvc\OobeDiscovery" /Disable
SchTasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /Disable
SchTasks /Change /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
SchTasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable 
SchTasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
SchTasks /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
SchTasks /Change /TN "\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents" /Disable
SchTasks /Change /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Disable
SchTasks /Change /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable


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


ECHO :: Optimization completed successfully. :: Script by S.H.E.I.K.H (GitHub: Sheikh98-DEV)


ECHO .
ECHO :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO :::: Warning. Press any key to shutdown or simply close this batch file. ::::
ECHO :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

Pause >null

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
Shutdown /S /T 5
