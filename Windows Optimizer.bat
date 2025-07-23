@ECHO OFF
SETLOCAL EnableDelayedExpansion
SET Version=1.0.0
Set ReleaseTime=Jul 23, 2025
Title Windows Optimizer Script - by S.H.E.I.K.H (V. %version%)

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Check to see if this batch file is being run as Administrator. If it is not, then rerun the batch file ::
:: automatically as admin and terminate the initial instance of the batch file.                           ::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

(Fsutil Dirty Query %SystemDrive%>nul 2>&1)||(PowerShell start """%~f0""" -verb RunAs & Exit /B) > NUL 2>&1

::::::::::::::::::::::::::::::::::::::::::::::::
:: End Routine to check if being run as Admin ::
::::::::::::::::::::::::::::::::::::::::::::::::

CD /D "%~dp0"
CLS

ECHO :::::::::::::::::::::::::::::::::::::::
ECHO ::     Windows Optimizer Script      ::
ECHO ::                                   ::
ECHO ::      Version %Version% (Stable)       ::
ECHO ::                                   ::
ECHO ::   %ReleaseTime% by  S.H.E.I.K.H    ::
ECHO ::                                   ::
ECHO ::       GitHub: Sheikh98-DEV        ::
ECHO :::::::::::::::::::::::::::::::::::::::
ECHO.
ECHO  For Post-install use only.
ECHO  Recommended to launch after Windows updates.
ECHO.
ECHO  Press any key to start optimization ...
Pause >nul 2>&1l


ECHO.
ECHO ::::::::::::::::::::::::::::::::
ECHO ::::: Starting Maintenance :::::
ECHO ::::::::::::::::::::::::::::::::
ECHO.

control wscui.cpl >nul 2>&1
MSchedExe.exe Start >nul 2>&1
ECHO Please wait until the end of maintenance,
ECHO Then return here and press any key to continue...
pause >nul 2>&1
ECHO Running idle tasks, please wait...
rundll32.exe advapi32.dll,ProcessIdleTasks >nul 2>&1

ECHO Done.


ECHO.
ECHO ::::::::::::::::::::::::
ECHO ::::: Closing Apps :::::
ECHO ::::::::::::::::::::::::
ECHO.

TaskKill /F /IM "msedge.exe" >nul 2>&1
TaskKill /F /IM "CrossDeviceResume.exe" >nul 2>&1

ECHO Done.


ECHO.
ECHO :::::::::::::::::::::::::
ECHO ::::: Checking Disk :::::
ECHO :::::::::::::::::::::::::
ECHO.

CHKDSK

ECHO Done.


ECHO.
ECHO ::::::::::::::::::::::::::::::
ECHO ::::: Cleaning DISM Temp :::::
ECHO ::::::::::::::::::::::::::::::
ECHO.

DISM /Online /Cleanup-Image /AnalyzeComponentStore
DISM /online /Remove-package /PackageName:Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.1742.1.10
DISM /Online /Cleanup-Image /StartComponentCleanup
DISM /Online /Cleanup-Image /StartComponentCleanup /ResetBase

ECHO Done.


ECHO.
ECHO :::::::::::::::::::::::::::::
ECHO ::::: Repairing Windows :::::
ECHO :::::::::::::::::::::::::::::
ECHO.

DISM /Online /Cleanup-Image /CheckHealth >nul 2>&1
DISM /Online /Cleanup-Image /ScanHealth
DISM /Online /Cleanup-Image /RestoreHealth
SFC /ScanNow
DISM /Online /Cleanup-Image /AnalyzeComponentStore
DISM /Online /Cleanup-Image /StartComponentCleanup
DISM /Online /Cleanup-Image /StartComponentcleanup /ResetBase

ECHO Done.


ECHO.
ECHO :::::::::::::::::::::::::::::::::
ECHO ::::: Setting Registry Keys :::::
ECHO :::::::::::::::::::::::::::::::::
ECHO.

REG Query "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Education" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Education" /V "IsEducationEnvironment" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Siuf\Rules" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Siuf\Rules" /V "NumberOfSIUFInPeriod" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /V "NetworkThrottlingIndex" /T "REG_DWORD" /D "4294967295" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /V "SystemResponsiveness" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /V "SensorPermissionState" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /V "RPSessionInterval" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /V "DODownloadMode" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /V "SearchOrderConfig" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /V "DisabledByGroupPolicy" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V "DisableTailoredExperiencesWithDiagnosticData" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /V "DoNotShowFeedbackNotifications" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /V "EnableActivityFeed" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /V "PublishUserActivities" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /V "UploadUserActivities" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /V "DisableAIDataAnalysis" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" /V "TurnOffWindowsCopilot" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /V "CrashDumpEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /V "DisableWpbtExecution" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /V "ClearPageFileAtShutdown" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Control\remote Assistance" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Control\remote Assistance" /V "fAllowToGetHelp" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /V "IRPStackSize" /T "REG_DWORD" /D "00000030" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /V "Status" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\Maps" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\Maps" /V "AutoUpdateEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /V "Value" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /V "Value" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /V "GlobalUserDisabled" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V "HideSCAMeetNow" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /V "ScoobeSystemSettingEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\Software\Policies\Microsoft\Windows\WindowsCopilot" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Policies\Microsoft\Windows\WindowsCopilot" /V "TurnOffWindowsCopilot" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\System\GameConfigStore" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\GameConfigStore" /V "GameDVR_EFSEFeatureFlags" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\System\GameConfigStore" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\GameConfigStore" /V "GameDVR_Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\System\GameConfigStore" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\GameConfigStore" /V "GameDVR_FSEBehavior" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\System\GameConfigStore" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\GameConfigStore" /V "GameDVR_HonorUserFSEBehaviorMode" /T "REG_DWORD" /D "1" /F) >nul 2>&1

ECHO Done.


ECHO.
ECHO ::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Microsoft Defender :::::
ECHO ::::::::::::::::::::::::::::::::::::::::
ECHO.

::::::::::::::::::::::::::::::::
ECHO Disabling Tamper Protection
::::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /V "TamperProtection" /T "REG_DWORD" /D "0" /F) >nul 2>&1

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling System Guard Runtime Monitor Broker (when disabled, it might cause BSOD Critical Process Died)
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
REG Query "HKLM\System\CurrentControlSet\Services\SgrmBroker" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\CurrentControlSet\Services\SgrmBroker" /V "Start" /T "REG_DWORD" /D "4" /F) >nul 2>&1

:::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling Windows Defender Security Center
:::::::::::::::::::::::::::::::::::::::::::::::
REG Query "HKLM\System\CurrentControlSet\Services\SecurityHealthService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /V "Start" /T "REG_DWORD" /D "4" /F) >nul 2>&1

::::::::::::::::::::::::::::::::::::::
ECHO Disabling Antivirus Notifications
::::::::::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications" /V "DisableNotifications" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /V "DisableEnhancedNotifications" /T "REG_DWORD" /D "1" /F) >nul 2>&1

:::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling Security and Maitenance Notification
:::::::::::::::::::::::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /V "Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1

:::::::::::::::::::::::::::::::::::
ECHO Disabling Real-time Protection
:::::::::::::::::::::::::::::::::::
REG Query "HKLM\Software\Policies\Microsoft\Windows Defender" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Policies\Microsoft\Windows Defender" /V "AllowFastServiceStartup" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\Software\Policies\Microsoft\Windows Defender" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Policies\Microsoft\Windows Defender" /V "DisableAntiSpyware" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\Software\Policies\Microsoft\Windows Defender" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Policies\Microsoft\Windows Defender" /V "DisableAntiVirus" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\Software\Policies\Microsoft\Windows Defender" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Policies\Microsoft\Windows Defender" /V "DisableSpecialRunningModes" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\Software\Policies\Microsoft\Windows Defender" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Policies\Microsoft\Windows Defender" /V "ServiceKeepAlive" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /V "MpEnablePus" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableBehaviorMonitoring" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableIOAVProtection" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableOnAccessProtection" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableRealtimeMonitoring" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableRoutinelyTakingAction" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableScanOnRealtimeEnable" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /V "DisableEnhancedNotifications" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /V "DisableBlockAtFirstSeen" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /V "SpynetReporting" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /V "SubmitSamplesConsent" /T "REG_DWORD" /D "2" /F) >nul 2>&1

::::::::::::::::::::::
ECHO Disabling Logging
::::::::::::::::::::::
REG Query "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /V "Start" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /V "Start" /T "REG_DWORD" /D "0" /F) >nul 2>&1

::::::::::::::::::::
ECHO Disabling Tasks
::::::::::::::::::::
SchTasks /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuaRD MDM policy Refresh" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable >nul 2>&1 
SchTasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable >nul 2>&1

:::::::::::::::::::::::::::
ECHO Disabling Systray icon
:::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /V "SecurityHealth" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "SecurityHealth" /F) >nul 2>&1

:::::::::::::::::::::::::::
ECHO Disabling Context Menu
:::::::::::::::::::::::::::
REG Query "HKCR\*\shellex\ContextMenuHandlers\EPP" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /F) >nul 2>&1
REG Query "HKCR\Directory\shellex\ContextMenuHandlers\EPP" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /F) >nul 2>&1
REG Query "HKCR\Drive\shellex\ContextMenuHandlers\EPP" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /F) >nul 2>&1

:::::::::::::::::::::::
ECHO Disabling Services
:::::::::::::::::::::::
REG Query "HKLM\System\CurrentControlSet\Services\MDCoreSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\CurrentControlSet\Services\MDCoreSvc" /V "Start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\System\CurrentControlSet\Services\WdBoot" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\CurrentControlSet\Services\WdBoot" /V "Start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\System\CurrentControlSet\Services\WdFilter" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\CurrentControlSet\Services\WdFilter" /V "Start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\System\CurrentControlSet\Services\WdNisDrv" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\CurrentControlSet\Services\WdNisDrv" /V "Start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\System\CurrentControlSet\Services\WdNisSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\CurrentControlSet\Services\WdNisSvc" /V "Start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\System\CurrentControlSet\Services\WinDefend" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\CurrentControlSet\Services\WinDefend" /V "Start" /T "REG_DWORD" /D "4" /F) >nul 2>&1

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling Web Threat Defense Service (Phishing Protection)
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
SC Stop "webthreatdefsvc" >nul 2>&1
SC Query "webthreatdefsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "webthreatdefsvc" Start=Disabled) >nul 2>&1

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling Web Threat Defense User Service (Phishing Protection)
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
SC Stop "webthreatdefusersvc" >nul 2>&1
SC Query "webthreatdefusersvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "webthreatdefusersvc" Start=Disabled) >nul 2>&1

::::::::::::::::::::::::::::::::::
ECHO Disabling Windows SmartScreen
::::::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /V "SmartScreenEnabled" /T "REG_SZ" /D "Off" /F) >nul 2>&1

:::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling SmartScreen Filter in Microsoft Edge
:::::::::::::::::::::::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Edge\SmartScreenEnabled" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Edge\SmartScreenEnabled" /VE /T "REG_DWORD" /D "0" /F) >nul 2>&1

::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling SmartScreen PUA in Microsoft Edge
::::::::::::::::::::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Edge\SmartScreenPuaEnabled" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Edge\SmartScreenPuaEnabled" /VE /T "REG_DWORD" /D "0" /F) >nul 2>&1

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling Windows SmartScreen for Windows Store Apps
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /V "EnableWebContentEvaluation" /T "REG_DWORD" /D "0" /F) >nul 2>&1

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling Smartscreen (to restore run "SFC /ScanNow")
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::
TakeOwn /S "%computername%" /U "%username%" /F "%WinDir%\System32\smartscreen.exe" >nul 2>&1
icacls "%WinDir%\System32\smartscreen.exe" /grant:r %username%:f >nul 2>&1
TaskKill /IM "smartscreen.exe" /F >nul 2>&1
DEL "%WinDir%\System32\smartscreen.exe" /S /F /Q >nul 2>&1

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling Smart App Control Blocking Legitimate Apps
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /V "VerifiedAndReputablePolicyState" /T "REG_DWORD" /D "0" /F) >nul 2>&1

::::::::::::::::::::::::::::::::::
ECHO Disabling Other Registry Keys
::::::::::::::::::::::::::::::::::

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V "SettingsPageVisibility" /T "REG_SZ" /D "hide:home" /F) >nul 2>&1
REG Query "HKLM\System\CurrentControlSet\Control\CI\Policy" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\CurrentControlSet\Control\CI\Policy" /V "DisableAntiSpyware" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\System\CurrentControlSet\Control\CI\Policy" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\CurrentControlSet\Control\CI\Policy" /V "DisableAntiVirus" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\System\CurrentControlSet\Control\CI\Policy" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\CurrentControlSet\Control\CI\Policy" /V "PUAProtection" /T "REG_DWORD" /D "0" /F) >nul 2>&1

ECHO.
ECHO Done.


ECHO.
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Auto-install Subscribed/Suggested Apps :::::
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO.

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "ContentDeliveryAllowed" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "FeaturemanagementEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "NumberOfSIUFInPeriod" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "OemPreInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEverEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SilentInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SoftLandingEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-310093Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338387Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338388Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338389Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338393Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353694Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353696Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353698Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContentEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SystemPaneSuggestionsEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\PushToInstall" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\PushToInstall" /V "DisablePushToInstall" /T "REG_DWORD" /D "1" /F) >nul 2>&1

ECHO Done.


ECHO.
ECHO :::::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Delivery Optimization :::::
ECHO :::::::::::::::::::::::::::::::::::::::::::
ECHO.

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /V "DODownloadMode" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /V "DODownloadMode" /T "REG_DWORD" /D "0" /F) >nul 2>&1

ECHO Done.


ECHO.
ECHO :::::::::::::::::::::::::::::::
ECHO ::::: Disabling BitLocker :::::
ECHO :::::::::::::::::::::::::::::::
ECHO.

REG Query "HKLM\SYSTEM\CurrentControlSet\Control\BitLocker" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Control\BitLocker" /V "PreventDeviceEncryption" /T "REG_DWORD" /D "1" /F) >nul 2>&1

ECHO Done.


ECHO.
ECHO :::::::::::::::::::::::::::::::
ECHO ::::: Disabling Chat Icon :::::
ECHO :::::::::::::::::::::::::::::::
ECHO.

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows" /V "ChatIcon" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "TaskbarMn" /T "REG_DWORD" /D "0" /F) >nul 2>&1

ECHO Done.


ECHO.
ECHO :::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Hibernation :::::
ECHO :::::::::::::::::::::::::::::::::
ECHO.

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /V "ShowHibernateOption" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /V "HiberbootEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\System\CurrentControlSet\Control\Session Manager\Power" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\CurrentControlSet\Control\Session Manager\Power" /V "HibernateEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
powercfg -h off >nul 2>&1
powercfg /hibernate off >nul 2>&1
powercfg.exe /hibernate off >nul 2>&1

ECHO Done.


ECHO.
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Windows Recovery Partition :::::
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::
ECHO.

reagentc /info >nul 2>&1
reagentc /Disable >nul 2>&1

ECHO Done.


ECHO.
ECHO ::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Reserved Storage :::::
ECHO ::::::::::::::::::::::::::::::::::::::
ECHO.

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /V "MiscPolicyInfo" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /V "PassedPolicy" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /V "ShippedWithReserves" /T "REG_DWORD" /D "0" /F) >nul 2>&1
fsutil storagereserve query C: >nul 2>&1
DISM /Online /Set-ReservedStorageState /State:Disabled /Quiet /NoRestart >nul 2>&1

ECHO Done.


ECHO.
ECHO ::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling NTFS Last Access :::::
ECHO ::::::::::::::::::::::::::::::::::::::
ECHO.

REG Query "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /V "NtfsDisableLastAccessUpdate" /T "REG_DWORD" /D "80000001" /F) >nul 2>&1
fsutil behavior set disablelastaccess 1 >nul 2>&1

ECHO Done.


ECHO.
ECHO :::::::::::::::::::::::::::::::::
ECHO ::::: Enabling TRIM for SSD :::::
ECHO :::::::::::::::::::::::::::::::::
ECHO.

fsutil behavior set disabledeletenotify 0 >nul 2>&1

ECHO Done.


ECHO.
ECHO :::::::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Windows Error Reporting :::::
ECHO :::::::::::::::::::::::::::::::::::::::::::::
ECHO.

:::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling Microsoft Support Diagnostic Tool MSDT
:::::::::::::::::::::::::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /V "DisableQueryremoteServer" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /V "EnableQueryremoteServer" /T "REG_DWORD" /D "0" /F) >nul 2>&1

::::::::::::::::::::::::::::::
ECHO Disabling System Debugger
::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" /V "Auto" /T "REG_SZ" /D "0" /F) >nul 2>&1

::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling Windows Error Reporting Registry keys
::::::::::::::::::::::::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\PCHealth\ErrorReporting" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\PCHealth\ErrorReporting" /V "DoReport" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /V "Disabled" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Consent" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Consent" /V "DefaultConsent" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Consent" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Consent" /V "DefaultOverrideBehavior" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /V "Disabled" /T "REG_DWORD" /D "1" /F) >nul 2>&1

::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling WER Sending Second-level Data
::::::::::::::::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /V "DontSendAdditionalData" /T "REG_DWORD" /D "1" /F) >nul 2>&1

::::::::::::::::::::::::::::::::::::::::
ECHO Disabling WER Crash Dialogs, Popups
::::::::::::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\PCHealth\ErrorReporting" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\PCHealth\ErrorReporting" /V "ShowUI" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /V "DontShowUI" /T "REG_DWORD" /D "1" /F) >nul 2>&1

::::::::::::::::::::::::::
ECHO Disabling WER Logging
::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /V "LoggingDisabled" /T "REG_DWORD" /D "1" /F) >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable >nul 2>&1

ECHO.
ECHO Done.


ECHO.
ECHO ::::::::::::::::::::::::::::::::::::
ECHO ::::: Windows Explorer Options :::::
ECHO ::::::::::::::::::::::::::::::::::::
ECHO.

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /V "PeopleBand" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /V "LongPathsEnabled" /T "REG_DWORD" /D "1" /F) >nul 2>&1

::::::::::::::::::::::::::::::::::::
ECHO Disabling Recently Used Folders
::::::::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /V "ShowRecent" /T "REG_DWORD" /D "0" /F) >nul 2>&1

::::::::::::::::::::::::::::::::::::::
ECHO Disabling Frequently Used Folders
::::::::::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /V "ShowFrequent" /T "REG_DWORD" /D "0" /F) >nul 2>&1

:::::::::::::::::::::::::::::::::::::::::
ECHO Disabling Show Files from Office.com
:::::::::::::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /V "ShowCloudFilesInQuickAccess" /T "REG_DWORD" /D "0" /F) >nul 2>&1

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling Network Icon from Navigation Panel / Right in Nav Panel
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
REG Query "HKCR\CLSID" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCR\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\ShellFolder" /V "Attributes" /T "REG_DWORD" /D "2962489444" /F) >nul 2>&1

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling Gallery from Navigation Pane in File Explorer
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Classes\CLSID" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" /V "System.IsPinnedToNameSpaceTree" /T "REG_DWORD" /D "0" /F) >nul 2>&1

:::::::::::::::::::::::::::::::::::::
ECHO Disabling 3D Folders from This PC
:::::::::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /F) >nul 2>&1

::::::::::::::::::::::::::::::::::::::::::::::
ECHO Disabling Home (Quick access)from This PC
::::::::::::::::::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /V "HubMode" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /F) >nul 2>&1

::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Setting Show Hidden Files, Folders and Drives
::::::::::::::::::::::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "Hidden" /T "REG_DWORD" /D "1" /F) >nul 2>&1

:::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Setting Show Extensions for Known File Types
:::::::::::::::::::::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "HideFileExt" /T "REG_DWORD" /D "0" /F) >nul 2>&1

::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Setting Always Show More Details in Copy Dialog
::::::::::::::::::::::::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /V "EnthusiastMode" /T "REG_DWORD" /D "1" /F) >nul 2>&1

::::::::::::::::::::::::::::::::::::::::::
ECHO Setting Open File Explorer to This PC
::::::::::::::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "LaunchTo" /T "REG_DWORD" /D "1" /F) >nul 2>&1

ECHO.
ECHO Done.


ECHO.
ECHO :::::::::::::::::::::::::::::::
ECHO ::::: Disabling Telemetry :::::
ECHO :::::::::::::::::::::::::::::::
ECHO.

REG Query "HKLM\SOFTWARE\Microsoft\InputPersonalization" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\InputPersonalization" /V "RestrictImplicitInkCollection" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\InputPersonalization" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\InputPersonalization" /V "RestrictImplicitTextCollection" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /V "HarvestContacts" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Input\TIPC" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Input\TIPC" /V "Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\MediaPlayer\Preferences" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\MediaPlayer\Preferences" /V "UsageTracking" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Personalization\Settings" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Personalization\Settings" /V "AcceptedPrivacyPolicy" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /V "HasAccepted" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /V "Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "TaskbarMn" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /V "AllowTelemetry" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /V "MaxTelemetryAllowed" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /V "TailoredExperiencesWithDiagnosticDataEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /V "NoGenTicket" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /V "AllowTelemetry" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /V "DoNotShowFeedbackNotifications" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" /V "ChatIcon" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\15.0\osm" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\15.0\osm" /V "enablefileobfuscation" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\15.0\osm" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\15.0\osm" /V "enablelogging" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\15.0\osm" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\15.0\osm" /V "enableupload" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common" /V "qmenable" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common" /V "sendcustomerdata" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common" /V "updatereliabilitydata" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" /V "enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" /V "includescreenshot" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\internet" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\internet" /V "useonlinecontent" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\ptwatson" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\ptwatson" /V "ptwoptin" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" /V "blockcontentexecutionfrominternet" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm" /V "enablefileobfuscation" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm" /V "enablelogging" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm" /V "enableupload" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "accesssolution" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "olksolution" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "onenotesolution" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "pptsolution" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "projectsolution" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "publishersolution" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "visiosolution" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "wdsolution" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "xlsolution" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "agave" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "appaddins" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "comaddins" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "documentfiles" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "templatefiles" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /V "level" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" /V "blockcontentexecutionfrominternet" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\word\security" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\word\security" /V "blockcontentexecutionfrominternet" /T "REG_DWORD" /D "0" /F) >nul 2>&1
SETX POWERSHELL_TELEMETRY_OPTOUT 1 >nul 2>&1
SchTasks /Change /Disable /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" >nul 2>&1
SchTasks /Change /Disable /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" >nul 2>&1
SchTasks /Change /Disable /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" >nul 2>&1
SchTasks /Change /Disable /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" >nul 2>&1
SchTasks /Change /Disable /TN "\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents" >nul 2>&1
SchTasks /Change /Disable /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" >nul 2>&1
SchTasks /Change /Disable /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting" >nul 2>&1

ECHO Done.


ECHO.
ECHO ::::::::::::::::::::::::::::::
ECHO ::::: Disabling OneDrive :::::
ECHO ::::::::::::::::::::::::::::::
ECHO.

:::::::::::::::::::::
ECHO Killing OneDrive
:::::::::::::::::::::
TaskKill /F /IM "OneDrive.exe" >nul 2>&1

:::::::::::::::::::::::::::::::::
ECHO Running OneDrive Uninstaller
:::::::::::::::::::::::::::::::::
if exist %SystemRoot%\System32\OneDriveSetup.exe (
	start /wait %SystemRoot%\System32\OneDriveSetup.exe /uninstall >nul 2>&1
)else (
	start /wait %SystemRoot%\SysWOW64\OneDriveSetup.exe /uninstall >nul 2>&1
)

::::::::::::::::::::::::::::::::::::::
ECHO Removing OneDrive Scheduled Tasks
::::::::::::::::::::::::::::::::::::::
for /F "tokens=1 delims=," %%x in ('schtasks /Query /Fo csv ^| find "OneDrive"')do schtasks /Delete /TN %%x /F >nul 2>&1

::::::::::::::::::::::::::::::::
ECHO Removing OneDrive Shortcuts
::::::::::::::::::::::::::::::::
DEL "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Microsoft OneDrive.lnk" /S /F /Q >nul 2>&1
DEL "%APPDATA%\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" /S /F /Q >nul 2>&1
DEL "%USERPROFILE%\Links\OneDrive.lnk" /S /F /Q >nul 2>&1

::::::::::::::::::::::::::::::::::::::::::
ECHO Removing OneDrive Related Directories
::::::::::::::::::::::::::::::::::::::::::
RD "%UserProfile%\OneDrive" /Q /S  >nul 2>&1
RD "%SystemDrive%\OneDriveTemp" /Q /S >nul 2>&1
RD "%LocalAppData%\Microsoft\OneDrive" /Q /S >nul 2>&1
RD "%ProgramData%\Microsoft OneDrive" /Q /S >nul 2>&1

:::::::::::::::::::::::::::::::::::
ECHO Removing Related Registry Keys
:::::::::::::::::::::::::::::::::::
REG Query "HKCR\CLSID" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKCR\CLSID\{018D5C66-4533-4308-9B53-224DE2ED1FE6}" /F) >nul 2>&1
REG Query "HKCR\Wow6432Node\CLSID" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4308-9B53-224DE2ED1FE6}" /F) >nul 2>&1

:::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Removing OneDrive from Explorer/Quick Access
:::::::::::::::::::::::::::::::::::::::::::::::::
REG Query "HKCR\CLSID" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCR\CLSID\{018D5C66-4533-4308-9B53-224DE2ED1FE6}" /V "System.IsPinnedToNameSpaceTree" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCR\Wow6432Node" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCR\Wow6432Node\{018D5C66-4533-4308-9B53-224DE2ED1FE6}" /V "System.IsPinnedToNameSpaceTree" /T "REG_DWORD" /D "0" /F) >nul 2>&1

::::::::::::::::::::::
ECHO Disabling OneSync
::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /V "DisableFileSyncNGSC" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /V "DisableFileSync" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /V "DisableMeteredNetworkFileSync" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /V "DisableLibrariesDefaultSaveToOneDrive" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\OneDrive" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\OneDrive" /V "DisablePersonalSync" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\OneDrive" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\OneDrive" /V "PreventNetworkTrafficPreUserSignIn" /T "REG_DWORD" /D "1" /F) >nul 2>&1

ECHO.
ECHO Done.


ECHO.
ECHO ::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Location Services  :::::
ECHO ::::::::::::::::::::::::::::::::::::::::
ECHO.

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /V "DisableLocation" /D "1" /T "REG_DWORD" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /V "DisableLocationScripting" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /V "DisableWindowsLocationProvider" /T "REG_DWORD" /D "1" /F) >nul 2>&1

ECHO Done.


ECHO.
ECHO ::::::::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Cloud Voice Recognation  :::::
ECHO ::::::::::::::::::::::::::::::::::::::::::::::
ECHO.

REG Query "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /V "HasAccepted" /T "REG_DWORD" /D "0" /F) >nul 2>&1

ECHO Done.


ECHO.
ECHO ::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Bing in Start Menu :::::
ECHO ::::::::::::::::::::::::::::::::::::::::
ECHO.

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /V "DisableSearchBoxSuggestions" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /V "ShowRunAsDifferentUserInStart" /T "REG_DWORD" /D "1" /F) >nul 2>&1

ECHO Done.


ECHO.
ECHO :::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Opting Out from Windows Privacy Consent :::::
ECHO :::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO.

REG Query "HKLM\SOFTWARE\Microsoft\Personalization\Settings" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Personalization\Settings" /V "AcceptedPrivacyPolicy" /T "REG_DWORD" /D "0" /F) >nul 2>&1

ECHO Done.


ECHO.
ECHO ::::::::::::::::::::::::::::
ECHO ::::: Disabling Search :::::
ECHO ::::::::::::::::::::::::::::
ECHO.

REG Query "HKLM\SOFTWARE\Microsoft\Personalization\Settings" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Personalization\Settings" /V "AcceptedPrivacyPolicy" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" /V "value" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "BingSearchEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "CanCortanaBeEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "CortanaEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "DeviceHistoryEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "HistoryViewEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowCloudSearch" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowCortana" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowCortanaAboveLock" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowSearchToUseLocation" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchPrivacy" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchUseWeb" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchUseWebOverMeteredConnections" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "DisableWebSearch" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "DisableremovableDriveIndexing" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "PreventUsingAdvancedIndexingOptions" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\services\TermServicentVersion\Search" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\services\TermServicentVersion\Search" /V "AllowCortana" /T "REG_DWORD" /D "0" /F) >nul 2>&1

ECHO Done.


ECHO.
ECHO :::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling DevHome and Outlook :::::
ECHO :::::::::::::::::::::::::::::::::::::::::
ECHO.

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\OutlookUpdate" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\OutlookUpdate" /V "workCompleted" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\DevHomeUpdate" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\DevHomeUpdate" /V "workCompleted" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKLM\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKLM\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate" /F) >nul 2>&1

ECHO Done.


ECHO.
ECHO ::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Sponsored Apps :::::
ECHO ::::::::::::::::::::::::::::::::::::
ECHO.

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "ContentDeliveryAllowed" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "FeatureManagementEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "OemPreInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEverEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SilentInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SoftLandingEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-310093Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338388Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338389Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338393Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353694Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353696Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContentEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SystemPaneSuggestionsEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\PushToInstall" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\PushToInstall" /V "DisablePushToInstall" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V "DisableCloudOptimizedContent" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V "DisableConsumerAccountStateContent" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V "DisableWindowsConsumerFeatures" /T "REG_DWORD" /D "1" /F) >nul 2>&1

ECHO Done.


ECHO.
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Deleting App Compatibility Appraiser and Assistant :::::
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO.

REG Query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0600DD45-FAF2-4131-A006-0B17509B9F78}" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /V "DisablePCA" /T "REG_DWORD" /D "2" /F) >nul 2>&1

ECHO Done.


ECHO.
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Deleting Customer Experiment Improvement Program :::::
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO.

REG Query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{4738DE7A-BCC1-4E2D-B1B0-CADB044BFA81}" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{6FAC31FA-4A85-4E64-BFD5-2154FF4594B3}" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{FC931F16-B50A-472E-B061-B6F79A71EF59}" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client" /V "CEIP" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\SQMClient" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient" /V "CorporateSQMURL" /T "REG_SZ" /D "0.0.0.0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /V "CEIPEnable" /T "REG_DWORD" /D "0" /F) >nul 2>&1

ECHO Done.


ECHO.
ECHO :::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Deleting Program Data Updater :::::
ECHO :::::::::::::::::::::::::::::::::::::::::
ECHO.

REG Query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0671EB05-7D95-4153-A32B-1426B9FE61DB}" /F) >nul 2>&1

ECHO Done.


ECHO.
ECHO ::::::::::::::::::::::::::::::::::::
ECHO ::::: Deleting Autocheck Proxy :::::
ECHO ::::::::::::::::::::::::::::::::::::
ECHO.

REG Query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{87BF85F4-2CE1-4160-96EA-52F554AA28A2}" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{8A9C643C-3D74-4099-B6BD-9C6D170898B1}" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{E3176A65-4E44-4ED3-AA73-3283660ACB9C}" /F) >nul 2>&1

ECHO Done.


ECHO.
ECHO ::::::::::::::::::::::::::
ECHO ::::: Disabling Xbox :::::
ECHO ::::::::::::::::::::::::::
ECHO.

REG Query "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /V "value" /T "REG_SZ" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" /V "ActivationType" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /V "AllowGameDVR" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\System\GameConfigStore" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\GameConfigStore" /V "GameDVR_DXGIHonorFSEWindowsCompatible" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\System\GameConfigStore" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\GameConfigStore" /V "GameDVR_EFSEFeatureFlags" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\System\GameConfigStore" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\GameConfigStore" /V "GameDVR_Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\System\GameConfigStore" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\GameConfigStore" /V "GameDVR_Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\System\GameConfigStore" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\GameConfigStore" /V "GameDVR_FSEBehaviorMode" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\System\GameConfigStore" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\System\GameConfigStore" /V "GameDVR_HonorUserFSEBehaviorMode" /T "REG_DWORD" /D "0" /F) >nul 2>&1

ECHO Done.


ECHO.
ECHO :::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Sync Settings :::::
ECHO :::::::::::::::::::::::::::::::::::
ECHO.

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /V "SyncPolicy" /T "REG_DWORD" /D "5" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /V "Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /V "Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /V "Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /V "Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme" /V "Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /V "Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\PackageState" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\PackageState" /V "Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /V "Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /V "Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /V "Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableAppSyncSettingSync" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableAppSyncSettingSyncUserOverride" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableApplicationSettingSync" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableApplicationSettingSyncUserOverride" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableCredentialsSettingSync" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableCredentialsSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableDesktopThemeSettingSync" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableDesktopThemeSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisablePersonalizationSettingSync" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisablePersonalizationSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableSettingSync" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableSettingSyncUserOverride" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableStartLayoutSettingSync" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableStartLayoutSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableSyncOnPaidNetwork" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableWebBrowserSettingSync" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableWebBrowserSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableWindowsSettingSync" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableWindowsSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F) >nul 2>&1

ECHO Done.


ECHO.
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Handwriting, Inking and Contacts :::::
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO.

REG Query "HKLM\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /V "HarvestContacts" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /V "AllowInputPersonalization" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /V "RestrictImplicitInkCollection" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /V "PreventHandwritingErrorReports" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /V "PreventHandwritingDataSharing" /T "REG_DWORD" /D "2" /F) >nul 2>&1

ECHO Done.


ECHO.
ECHO :::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling App Launch Tracking :::::
ECHO :::::::::::::::::::::::::::::::::::::::::
ECHO.

REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "Start_TrackProgs" /T "REG_DWORD" /D "0" /F) >nul 2>&1

ECHO Done.


ECHO.
ECHO :::::::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Diagnostics and Privacy :::::
ECHO :::::::::::::::::::::::::::::::::::::::::::::
ECHO.

REG Query "HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\Microsoft.Microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\Microsoft.Microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /V "EnabledV9" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\Microsoft.Microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Privacy" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\Microsoft.Microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Privacy" /V "EnableEncryptedMediaExtensions" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Input\TIPC" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Input\TIPC" /V "Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /V "DiagnosticErrorText" /T "REG_SZ" /D "" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /V "DiagnosticLinkText" /T "REG_SZ" /D "" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /V "DiagnosticErrorText" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /V "Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /V "DisableInventory" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /V "DisableUAR" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /V "NoLockScreenCamera" /T "REG_DWORD" /D "1" /F) >nul 2>&1

ECHO Done.


ECHO.
ECHO :::::::::::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Windows Insider Experiments :::::
ECHO :::::::::::::::::::::::::::::::::::::::::::::::::
ECHO.

REG Query "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" /V "AllowExperimentation" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" /V "value" /T "REG_DWORD" /D "0" /F) >nul 2>&1

ECHO Done.

ECHO.
ECHO :::::::::::::::::::::::::::::
ECHO ::::: Disabling Copilot :::::
ECHO :::::::::::::::::::::::::::::
ECHO.

REG Query "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /V "RestrictImplicitInkCollection" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /V "PreventHandwritingErrorReports" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /V "PreventHandwritingDataSharing" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /V "AllowInputPersonalization" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /V "HarvestContacts" /T "REG_DWORD" /D "0" /F) >nul 2>&1

ECHO Done.


ECHO.
ECHO ::::::::::::::::::::::::::::::::
ECHO ::::: Changing Apps Access :::::
ECHO ::::::::::::::::::::::::::::::::
ECHO.

:::::::::::::::::::::::::
ECHO Setting Account Info
:::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1

:::::::::::::::::::
ECHO Setting Radios
:::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1

::::::::::::::::::::::::
ECHO Setting Diagnostics
::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1

:::::::::::::::::::::
ECHO Setting Contacts
:::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1

:::::::::::::::::::::
ECHO Setting Calendar
:::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1

:::::::::::::::::::::::::
ECHO Setting Call History
:::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1

::::::::::::::::::
ECHO Setting Email
::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1

::::::::::::::::::
ECHO Setting Tasks
::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E390DF20-07DF-446D-B962-F5C953072741}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1

::::::::::::::::
ECHO Setting SMS
::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{21157C1F-2651-4CC1-90CA-1F28B02263F6}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1

:::::::::::::::::::::
ECHO Setting Contacts
:::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1

:::::::::::::::::::::
ECHO Setting Sms Send
:::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1

:::::::::::::::::::::
ECHO Setting Activity
:::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9D9E0118-1807-4F2E-96E4-2CE57142E196}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{B19F89AF-E3EB-444B-8DEA-202575A71599}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1

:::::::::::::::::::::
ECHO Setting Location
:::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1

:::::::::::::::::::::::::::::::::::::
ECHO Setting User Account Information
:::::::::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1

:::::::::::::::::::::::::
ECHO Setting Appointments
:::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1

:::::::::::::::::::::::::::::
ECHO Setting Location History
:::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E6AD100E-5F4E-44CD-BE0F-2265D88D14F5}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1

::::::::::::::::::::
ECHO Setting Sensors
::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E83AF229-8640-4D18-A213-E22675EBB2C3}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1

:::::::::::::::::::::::::::::::
ECHO Setting Phone Call History
:::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1

:::::::::::::::::::::::
ECHO Setting Phone Call
:::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{235B668D-B2AC-4864-B49C-ED1084F6C9D3}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1

:::::::::::::::::::::::::::::::::::::::
ECHO Setting User Notification Listener
:::::::::::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1


::::::::::::::::::::::::::::::::
ECHO Setting Other Registry Keys
::::::::::::::::::::::::::::::::
REG Query "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Browser" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Browser" /V "AllowAddressBarDropdown" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Experience" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Experience" /V "AllowCortana" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Experience" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Experience" /V "AllowTailoredExperiencesWithDiagnosticData" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /V "ModelDownloadAllowed" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /V "GlobalUserDisabled" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Microsoft\Windows\ScheduledDiagnostics" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Microsoft\Windows\ScheduledDiagnostics" /V "EnabledExecution" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Speech" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Speech" /V "AllowSpeechModelUpdate" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /V "DisableOnline" /T "REG_DWORD" /D "1" /F) >nul 2>&1

ECHO.
ECHO Done.


ECHO.
ECHO :::::::::::::::::::::::::
ECHO ::::: Edge Settings :::::
ECHO :::::::::::::::::::::::::
ECHO.

REG Query "HKLM\SOFTWARE\Policies\Microsoft\Edge" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "AlternateErrorPagesEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Edge" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "ConfigureDoNotTrack" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Edge" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "CryptoWalletEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Edge" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "DiagnosticData" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Edge" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "EdgeAssetDeliveryServiceEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Edge" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "EdgeCollectionsEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Edge" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "EdgeShoppingAssistantEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Edge" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "HideFirstRunExperience" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Edge" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "MicrosoftEdgeInsiderPromotionEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Edge" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "PersonalizationReportingEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Edge" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "ShowMicrosoftRewards" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Edge" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "ShowRecommendationsEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Edge" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "UserFeedbackAllowed" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Edge" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "WalletDonationEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\Edge" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V "WebWidgetAllowed" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" /V "CreateDesktopShortcutDefault" /T "REG_DWORD" /D "0" /F) >nul 2>&1

ECHO Done.


ECHO.
ECHO ::::::::::::::::::::::::::::
ECHO ::::: Setting Services :::::
ECHO ::::::::::::::::::::::::::::
ECHO.

::::::::::::::::::::::::::::
ECHO Disabling Some Services
::::::::::::::::::::::::::::
SC Query "AJRouter" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "AJRouter" Start=Disabled) >nul 2>&1
SC Query "AJRouter_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "AJRouter_*" Start=Disabled) >nul 2>&1
SC Query "AppVClient" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "AppVClient" Start=Disabled) >nul 2>&1
SC Query "AppVClient_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "AppVClient_*" Start=Disabled) >nul 2>&1
SC Query "BcastDVRUserService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "BcastDVRUserService" Start=Disabled) >nul 2>&1
SC Query "BcastDVRUserService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "BcastDVRUserService_*" Start=Disabled) >nul 2>&1
SC Query "DialogBlockingService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "DialogBlockingService" Start=Disabled) >nul 2>&1
SC Query "DialogBlockingService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "DialogBlockingService_*" Start=Disabled) >nul 2>&1
SC Query "Fax" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "Fax" Start=Disabled) >nul 2>&1
SC Query "Fax_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "Fax_*" Start=Disabled) >nul 2>&1
SC Query "MDCoreSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "MDCoreSvc" Start=Disabled) >nul 2>&1
SC Query "MDCoreSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "MDCoreSvc_*" Start=Disabled) >nul 2>&1
SC Query "MixedRealityOpenXRSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "MixedRealityOpenXRSvc" Start=Disabled) >nul 2>&1
SC Query "MixedRealityOpenXRSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "MixedRealityOpenXRSvc_*" Start=Disabled) >nul 2>&1
SC Query "MsKeyboardFilter" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "MsKeyboardFilter" Start=Disabled) >nul 2>&1
SC Query "MsKeyboardFilter_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "MsKeyboardFilter_*" Start=Disabled) >nul 2>&1
SC Query "NetTcpPortSharing" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "NetTcpPortSharing" Start=Disabled) >nul 2>&1
SC Query "NetTcpPortSharing_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "NetTcpPortSharing_*" Start=Disabled) >nul 2>&1
SC Query "OneSyncSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "OneSyncSvc" Start=Disabled) >nul 2>&1
SC Query "OneSyncSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "OneSyncSvc_*" Start=Disabled) >nul 2>&1
SC Query "P9RdrService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "P9RdrService" Start=Disabled) >nul 2>&1
SC Query "P9RdrService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "P9RdrService_*" Start=Disabled) >nul 2>&1
SC Query "RemoteAccess" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "RemoteAccess" Start=Disabled) >nul 2>&1
SC Query "RemoteAccess_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "RemoteAccess_*" Start=Disabled) >nul 2>&1
SC Query "RemoteRegistry" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "RemoteRegistry" Start=Disabled) >nul 2>&1
SC Query "RemoteRegistry_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "RemoteRegistry_*" Start=Disabled) >nul 2>&1
SC Query "SecurityHealthService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "SecurityHealthService" Start=Disabled) >nul 2>&1
SC Query "SecurityHealthService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "SecurityHealthService_*" Start=Disabled) >nul 2>&1
SC Query "Sense" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "Sense" Start=Disabled) >nul 2>&1
SC Query "Sense_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "Sense_*" Start=Disabled) >nul 2>&1
SC Query "SensorDataService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "SensorDataService" Start=Disabled) >nul 2>&1
SC Query "SensorDataService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "SensorDataService_*" Start=Disabled) >nul 2>&1
SC Query "SysMain" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "SysMain" Start=Disabled) >nul 2>&1
SC Query "SysMain_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "SysMain_*" Start=Disabled) >nul 2>&1
SC Query "UevAgentService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "UevAgentService" Start=Disabled) >nul 2>&1
SC Query "UevAgentService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "UevAgentService_*" Start=Disabled) >nul 2>&1
SC Query "WMPNetworkSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WMPNetworkSvc" Start=Disabled) >nul 2>&1
SC Query "WMPNetworkSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WMPNetworkSvc_*" Start=Disabled) >nul 2>&1
SC Query "WerSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WerSvc" Start=Disabled) >nul 2>&1
SC Query "WerSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WerSvc_*" Start=Disabled) >nul 2>&1
SC Query "WinDefend" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WinDefend" Start=Disabled) >nul 2>&1
SC Query "WinDefend_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WinDefend_*" Start=Disabled) >nul 2>&1
SC Query "XblAuthManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "XblAuthManager" Start=Disabled) >nul 2>&1
SC Query "XblAuthManager_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "XblAuthManager_*" Start=Disabled) >nul 2>&1
SC Query "XblGameSave" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "XblGameSave" Start=Disabled) >nul 2>&1
SC Query "XblGameSave_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "XblGameSave_*" Start=Disabled) >nul 2>&1
SC Query "XboxGipSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "XboxGipSvc" Start=Disabled) >nul 2>&1
SC Query "XboxGipSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "XboxGipSvc_*" Start=Disabled) >nul 2>&1
SC Query "XboxNetApiSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "XboxNetApiSvc" Start=Disabled) >nul 2>&1
SC Query "XboxNetApiSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "XboxNetApiSvc_*" Start=Disabled) >nul 2>&1
SC Query "mpssvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "mpssvc" Start=Disabled) >nul 2>&1
SC Query "mpssvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "mpssvc_*" Start=Disabled) >nul 2>&1
SC Query "shpamsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "shpamsvc" Start=Disabled) >nul 2>&1
SC Query "shpamsvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "shpamsvc_*" Start=Disabled) >nul 2>&1
SC Query "ssh-agent" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "ssh-agent" Start=Disabled) >nul 2>&1
SC Query "ssh-agent_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "ssh-agent_*" Start=Disabled) >nul 2>&1
SC Query "tzautoupdate" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "tzautoupdate" Start=Disabled) >nul 2>&1
SC Query "tzautoupdate_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "tzautoupdate_*" Start=Disabled) >nul 2>&1
SC Query "webthreatdefsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "webthreatdefsvc" Start=Disabled) >nul 2>&1
SC Query "webthreatdefsvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "webthreatdefsvc_*" Start=Disabled) >nul 2>&1
SC Query "webthreatdefusersvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "webthreatdefusersvc" Start=Disabled) >nul 2>&1
SC Query "webthreatdefusersvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "webthreatdefusersvc_*" Start=Disabled) >nul 2>&1
SC Query "workfolderssvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "workfolderssvc" Start=Disabled) >nul 2>&1
SC Query "workfolderssvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "workfolderssvc_*" Start=Disabled) >nul 2>&1
SC Query "wsearch" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "wsearch" Start=Disabled) >nul 2>&1
SC Query "wsearch_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "wsearch_*" Start=Disabled) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AJRouter" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AJRouter" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AJRouter_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AJRouter_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AppVClient" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AppVClient" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AppVClient_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AppVClient_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\BcastDVRUserService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\BcastDVRUserService" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\BcastDVRUserService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\BcastDVRUserService_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DialogBlockingService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DialogBlockingService" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DialogBlockingService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DialogBlockingService_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Fax" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Fax" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Fax_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Fax_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\MDCoreSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MDCoreSvc" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\MDCoreSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MDCoreSvc_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\MixedRealityOpenXRSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MixedRealityOpenXRSvc" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\MixedRealityOpenXRSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MixedRealityOpenXRSvc_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\MsKeyboardFilter" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MsKeyboardFilter" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\MsKeyboardFilter_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MsKeyboardFilter_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\OneSyncSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\OneSyncSvc" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\OneSyncSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\OneSyncSvc_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\P9RdrService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\P9RdrService" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\P9RdrService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\P9RdrService_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Sense" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Sense_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Sense_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SensorDataService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SensorDataService" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SensorDataService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SensorDataService_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SysMain" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SysMain" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SysMain_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SysMain_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\UevAgentService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UevAgentService" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\UevAgentService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UevAgentService_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WerSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WerSvc" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WerSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WerSvc_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\XboxGipSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\XboxGipSvc" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\XboxGipSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\XboxGipSvc_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\mpssvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\mpssvc" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\mpssvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\mpssvc_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\shpamsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\shpamsvc" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\shpamsvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\shpamsvc_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\ssh-agent" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ssh-agent" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\ssh-agent_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ssh-agent_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\tzautoupdate" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\tzautoupdate" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\tzautoupdate_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\tzautoupdate_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\webthreatdefsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\webthreatdefsvc" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\webthreatdefsvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\webthreatdefsvc_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\webthreatdefusersvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\webthreatdefusersvc" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\webthreatdefusersvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\webthreatdefusersvc_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\workfolderssvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\workfolderssvc" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\workfolderssvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\workfolderssvc_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wsearch" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wsearch" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wsearch_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wsearch_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1

::::::::::::::::::::::::::::::::::::
ECHO Setting Some Services as Manual
::::::::::::::::::::::::::::::::::::
SC Query "ALG" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "ALG" Start=Demand) >nul 2>&1
SC Query "ALG_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "ALG_*" Start=Demand) >nul 2>&1
SC Query "AarSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "AarSvc" Start=Demand) >nul 2>&1
SC Query "AarSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "AarSvc_*" Start=Demand) >nul 2>&1
SC Query "AppIDSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "AppIDSvc" Start=Demand) >nul 2>&1
SC Query "AppIDSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "AppIDSvc_*" Start=Demand) >nul 2>&1
SC Query "AppMgmt" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "AppMgmt" Start=Demand) >nul 2>&1
SC Query "AppMgmt_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "AppMgmt_*" Start=Demand) >nul 2>&1
SC Query "AppReadiness" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "AppReadiness" Start=Demand) >nul 2>&1
SC Query "AppReadiness_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "AppReadiness_*" Start=Demand) >nul 2>&1
SC Query "AppXSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "AppXSvc" Start=Demand) >nul 2>&1
SC Query "AppXSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "AppXSvc_*" Start=Demand) >nul 2>&1
SC Query "Appinfo" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "Appinfo" Start=Demand) >nul 2>&1
SC Query "Appinfo_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "Appinfo_*" Start=Demand) >nul 2>&1
SC Query "ApxSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "ApxSvc" Start=Demand) >nul 2>&1
SC Query "ApxSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "ApxSvc_*" Start=Demand) >nul 2>&1
SC Query "AssignedAccessManagerSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "AssignedAccessManagerSvc" Start=Demand) >nul 2>&1
SC Query "AssignedAccessManagerSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "AssignedAccessManagerSvc_*" Start=Demand) >nul 2>&1
SC Query "AxInstSV" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "AxInstSV" Start=Demand) >nul 2>&1
SC Query "AxInstSV_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "AxInstSV_*" Start=Demand) >nul 2>&1
SC Query "BDESVC" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "BDESVC" Start=Demand) >nul 2>&1
SC Query "BDESVC_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "BDESVC_*" Start=Demand) >nul 2>&1
SC Query "BITS" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "BITS" Start=Demand) >nul 2>&1
SC Query "BITS_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "BITS_*" Start=Demand) >nul 2>&1
SC Query "BTAGService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "BTAGService" Start=Demand) >nul 2>&1
SC Query "BTAGService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "BTAGService_*" Start=Demand) >nul 2>&1
SC Query "BluetoothUserService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "BluetoothUserService" Start=Demand) >nul 2>&1
SC Query "BluetoothUserService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "BluetoothUserService_*" Start=Demand) >nul 2>&1
SC Query "Browser" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "Browser" Start=Demand) >nul 2>&1
SC Query "Browser_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "Browser_*" Start=Demand) >nul 2>&1
SC Query "BthAvctpSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "BthAvctpSvc" Start=Demand) >nul 2>&1
SC Query "BthAvctpSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "BthAvctpSvc_*" Start=Demand) >nul 2>&1
SC Query "CDPSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "CDPSvc" Start=Demand) >nul 2>&1
SC Query "CDPSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "CDPSvc_*" Start=Demand) >nul 2>&1
SC Query "CDPUserSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "CDPUserSvc" Start=Demand) >nul 2>&1
SC Query "CDPUserSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "CDPUserSvc_*" Start=Demand) >nul 2>&1
SC Query "COMSysApp" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "COMSysApp" Start=Demand) >nul 2>&1
SC Query "COMSysApp_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "COMSysApp_*" Start=Demand) >nul 2>&1
SC Query "CaptureService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "CaptureService" Start=Demand) >nul 2>&1
SC Query "CaptureService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "CaptureService_*" Start=Demand) >nul 2>&1
SC Query "CertPropSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "CertPropSvc" Start=Demand) >nul 2>&1
SC Query "CertPropSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "CertPropSvc_*" Start=Demand) >nul 2>&1
SC Query "ClipSVC" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "ClipSVC" Start=Demand) >nul 2>&1
SC Query "ClipSVC_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "ClipSVC_*" Start=Demand) >nul 2>&1
SC Query "CloudBackupRestoreSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "CloudBackupRestoreSvc" Start=Demand) >nul 2>&1
SC Query "CloudBackupRestoreSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "CloudBackupRestoreSvc_*" Start=Demand) >nul 2>&1
SC Query "ConsentUxUserSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "ConsentUxUserSvc" Start=Demand) >nul 2>&1
SC Query "ConsentUxUserSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "ConsentUxUserSvc_*" Start=Demand) >nul 2>&1
SC Query "CredentialEnrollmentManagerUserSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "CredentialEnrollmentManagerUserSvc" Start=Demand) >nul 2>&1
SC Query "CredentialEnrollmentManagerUserSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "CredentialEnrollmentManagerUserSvc_*" Start=Demand) >nul 2>&1
SC Query "CscService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "CscService" Start=Demand) >nul 2>&1
SC Query "CscService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "CscService_*" Start=Demand) >nul 2>&1
SC Query "DPS" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "DPS" Start=Demand) >nul 2>&1
SC Query "DPS_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "DPS_*" Start=Demand) >nul 2>&1
SC Query "DcpSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "DcpSvc" Start=Demand) >nul 2>&1
SC Query "DcpSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "DcpSvc_*" Start=Demand) >nul 2>&1
SC Query "DevQueryBroker" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "DevQueryBroker" Start=Demand) >nul 2>&1
SC Query "DevQueryBroker_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "DevQueryBroker_*" Start=Demand) >nul 2>&1
SC Query "DeviceAssociationBrokerSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "DeviceAssociationBrokerSvc" Start=Demand) >nul 2>&1
SC Query "DeviceAssociationBrokerSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "DeviceAssociationBrokerSvc_*" Start=Demand) >nul 2>&1
SC Query "DeviceAssociationService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "DeviceAssociationService" Start=Demand) >nul 2>&1
SC Query "DeviceAssociationService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "DeviceAssociationService_*" Start=Demand) >nul 2>&1
SC Query "DeviceInstall" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "DeviceInstall" Start=Demand) >nul 2>&1
SC Query "DeviceInstall_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "DeviceInstall_*" Start=Demand) >nul 2>&1
SC Query "DevicePickerUserSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "DevicePickerUserSvc" Start=Demand) >nul 2>&1
SC Query "DevicePickerUserSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "DevicePickerUserSvc_*" Start=Demand) >nul 2>&1
SC Query "DevicesFlowUserSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "DevicesFlowUserSvc" Start=Demand) >nul 2>&1
SC Query "DevicesFlowUserSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "DevicesFlowUserSvc_*" Start=Demand) >nul 2>&1
SC Query "DiagTrack" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "DiagTrack" Start=Demand) >nul 2>&1
SC Query "DiagTrack_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "DiagTrack_*" Start=Demand) >nul 2>&1
SC Query "DisplayEnhancementService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "DisplayEnhancementService" Start=Demand) >nul 2>&1
SC Query "DisplayEnhancementService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "DisplayEnhancementService_*" Start=Demand) >nul 2>&1
SC Query "DmEnrollmentSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "DmEnrollmentSvc" Start=Demand) >nul 2>&1
SC Query "DmEnrollmentSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "DmEnrollmentSvc_*" Start=Demand) >nul 2>&1
SC Query "DoSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "DoSvc" Start=Demand) >nul 2>&1
SC Query "DoSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "DoSvc_*" Start=Demand) >nul 2>&1
SC Query "DsSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "DsSvc" Start=Demand) >nul 2>&1
SC Query "DsSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "DsSvc_*" Start=Demand) >nul 2>&1
SC Query "DsmSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "DsmSvc" Start=Demand) >nul 2>&1
SC Query "DsmSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "DsmSvc_*" Start=Demand) >nul 2>&1
SC Query "DusmSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "DusmSvc" Start=Demand) >nul 2>&1
SC Query "DusmSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "DusmSvc_*" Start=Demand) >nul 2>&1
SC Query "EFS" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "EFS" Start=Demand) >nul 2>&1
SC Query "EFS_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "EFS_*" Start=Demand) >nul 2>&1
SC Query "EapHost" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "EapHost" Start=Demand) >nul 2>&1
SC Query "EapHost_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "EapHost_*" Start=Demand) >nul 2>&1
SC Query "EntAppSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "EntAppSvc" Start=Demand) >nul 2>&1
SC Query "EntAppSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "EntAppSvc_*" Start=Demand) >nul 2>&1
SC Query "FDResPub" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "FDResPub" Start=Demand) >nul 2>&1
SC Query "FDResPub_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "FDResPub_*" Start=Demand) >nul 2>&1
SC Query "FontCache" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "FontCache" Start=Demand) >nul 2>&1
SC Query "FontCache_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "FontCache_*" Start=Demand) >nul 2>&1
SC Query "FrameServer" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "FrameServer" Start=Demand) >nul 2>&1
SC Query "FrameServerMonitor" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "FrameServerMonitor" Start=Demand) >nul 2>&1
SC Query "FrameServerMonitor_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "FrameServerMonitor_*" Start=Demand) >nul 2>&1
SC Query "FrameServer_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "FrameServer_*" Start=Demand) >nul 2>&1
SC Query "GameInputSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "GameInputSvc" Start=Demand) >nul 2>&1
SC Query "GameInputSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "GameInputSvc_*" Start=Demand) >nul 2>&1
SC Query "GraphicsPerfSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "GraphicsPerfSvc" Start=Demand) >nul 2>&1
SC Query "GraphicsPerfSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "GraphicsPerfSvc_*" Start=Demand) >nul 2>&1
SC Query "HomeGroupListener" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "HomeGroupListener" Start=Demand) >nul 2>&1
SC Query "HomeGroupListener_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "HomeGroupListener_*" Start=Demand) >nul 2>&1
SC Query "HomeGroupProvider" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "HomeGroupProvider" Start=Demand) >nul 2>&1
SC Query "HomeGroupProvider_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "HomeGroupProvider_*" Start=Demand) >nul 2>&1
SC Query "HvHost" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "HvHost" Start=Demand) >nul 2>&1
SC Query "HvHost_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "HvHost_*" Start=Demand) >nul 2>&1
SC Query "IEEtwCollectorService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "IEEtwCollectorService" Start=Demand) >nul 2>&1
SC Query "IEEtwCollectorService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "IEEtwCollectorService_*" Start=Demand) >nul 2>&1
SC Query "InstallService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "InstallService" Start=Demand) >nul 2>&1
SC Query "InstallService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "InstallService_*" Start=Demand) >nul 2>&1
SC Query "InventorySvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "InventorySvc" Start=Demand) >nul 2>&1
SC Query "InventorySvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "InventorySvc_*" Start=Demand) >nul 2>&1
SC Query "IpxlatCfgSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "IpxlatCfgSvc" Start=Demand) >nul 2>&1
SC Query "IpxlatCfgSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "IpxlatCfgSvc_*" Start=Demand) >nul 2>&1
SC Query "KeyIso" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "KeyIso" Start=Demand) >nul 2>&1
SC Query "KeyIso_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "KeyIso_*" Start=Demand) >nul 2>&1
SC Query "KtmRm" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "KtmRm" Start=Demand) >nul 2>&1
SC Query "KtmRm_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "KtmRm_*" Start=Demand) >nul 2>&1
SC Query "LicenseManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "LicenseManager" Start=Demand) >nul 2>&1
SC Query "LicenseManager_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "LicenseManager_*" Start=Demand) >nul 2>&1
SC Query "LocalKdc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "LocalKdc" Start=Demand) >nul 2>&1
SC Query "LocalKdc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "LocalKdc_*" Start=Demand) >nul 2>&1
SC Query "LxpSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "LxpSvc" Start=Demand) >nul 2>&1
SC Query "LxpSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "LxpSvc_*" Start=Demand) >nul 2>&1
SC Query "MSDTC" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "MSDTC" Start=Demand) >nul 2>&1
SC Query "MSDTC_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "MSDTC_*" Start=Demand) >nul 2>&1
SC Query "MSiSCSI" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "MSiSCSI" Start=Demand) >nul 2>&1
SC Query "MSiSCSI_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "MSiSCSI_*" Start=Demand) >nul 2>&1
SC Query "MapsBroker" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "MapsBroker" Start=Demand) >nul 2>&1
SC Query "MapsBroker_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "MapsBroker_*" Start=Demand) >nul 2>&1
SC Query "McmSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "McmSvc" Start=Demand) >nul 2>&1
SC Query "McmSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "McmSvc_*" Start=Demand) >nul 2>&1
SC Query "McpManagementService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "McpManagementService" Start=Demand) >nul 2>&1
SC Query "McpManagementService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "McpManagementService_*" Start=Demand) >nul 2>&1
SC Query "MessagingService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "MessagingService" Start=Demand) >nul 2>&1
SC Query "MessagingService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "MessagingService_*" Start=Demand) >nul 2>&1
SC Query "MicrosoftEdgeElevationService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "MicrosoftEdgeElevationService" Start=Demand) >nul 2>&1
SC Query "MicrosoftEdgeElevationService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "MicrosoftEdgeElevationService_*" Start=Demand) >nul 2>&1
SC Query "NPSMSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "NPSMSvc" Start=Demand) >nul 2>&1
SC Query "NPSMSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "NPSMSvc_*" Start=Demand) >nul 2>&1
SC Query "NaturalAuthentication" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "NaturalAuthentication" Start=Demand) >nul 2>&1
SC Query "NaturalAuthentication_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "NaturalAuthentication_*" Start=Demand) >nul 2>&1
SC Query "NcaSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "NcaSvc" Start=Demand) >nul 2>&1
SC Query "NcaSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "NcaSvc_*" Start=Demand) >nul 2>&1
SC Query "NcbService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "NcbService" Start=Demand) >nul 2>&1
SC Query "NcbService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "NcbService_*" Start=Demand) >nul 2>&1
SC Query "NcdAutoSetup" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "NcdAutoSetup" Start=Demand) >nul 2>&1
SC Query "NcdAutoSetup_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "NcdAutoSetup_*" Start=Demand) >nul 2>&1
SC Query "NetSetupSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "NetSetupSvc" Start=Demand) >nul 2>&1
SC Query "NetSetupSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "NetSetupSvc_*" Start=Demand) >nul 2>&1
SC Query "Netlogon" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "Netlogon" Start=Demand) >nul 2>&1
SC Query "Netlogon_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "Netlogon_*" Start=Demand) >nul 2>&1
SC Query "Netman" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "Netman" Start=Demand) >nul 2>&1
SC Query "Netman_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "Netman_*" Start=Demand) >nul 2>&1
SC Query "NgcCtnrSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "NgcCtnrSvc" Start=Demand) >nul 2>&1
SC Query "NgcCtnrSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "NgcCtnrSvc_*" Start=Demand) >nul 2>&1
SC Query "NgcSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "NgcSvc" Start=Demand) >nul 2>&1
SC Query "NgcSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "NgcSvc_*" Start=Demand) >nul 2>&1
SC Query "NlaSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "NlaSvc" Start=Demand) >nul 2>&1
SC Query "NlaSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "NlaSvc_*" Start=Demand) >nul 2>&1
SC Query "PNRPAutoREG" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "PNRPAutoREG" Start=Demand) >nul 2>&1
SC Query "PNRPAutoREG_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "PNRPAutoREG_*" Start=Demand) >nul 2>&1
SC Query "PNRPsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "PNRPsvc" Start=Demand) >nul 2>&1
SC Query "PNRPsvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "PNRPsvc_*" Start=Demand) >nul 2>&1
SC Query "PcaSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "PcaSvc" Start=Demand) >nul 2>&1
SC Query "PcaSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "PcaSvc_*" Start=Demand) >nul 2>&1
SC Query "PeerDistSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "PeerDistSvc" Start=Demand) >nul 2>&1
SC Query "PeerDistSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "PeerDistSvc_*" Start=Demand) >nul 2>&1
SC Query "PenService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "PenService" Start=Demand) >nul 2>&1
SC Query "PenService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "PenService_*" Start=Demand) >nul 2>&1
SC Query "PerfHost" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "PerfHost" Start=Demand) >nul 2>&1
SC Query "PerfHost_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "PerfHost_*" Start=Demand) >nul 2>&1
SC Query "PhoneSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "PhoneSvc" Start=Demand) >nul 2>&1
SC Query "PhoneSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "PhoneSvc_*" Start=Demand) >nul 2>&1
SC Query "PimIndexMaintenanceSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "PimIndexMaintenanceSvc" Start=Demand) >nul 2>&1
SC Query "PimIndexMaintenanceSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "PimIndexMaintenanceSvc_*" Start=Demand) >nul 2>&1
SC Query "PlugPlay" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "PlugPlay" Start=Demand) >nul 2>&1
SC Query "PlugPlay_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "PlugPlay_*" Start=Demand) >nul 2>&1
SC Query "PolicyAgent" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "PolicyAgent" Start=Demand) >nul 2>&1
SC Query "PolicyAgent_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "PolicyAgent_*" Start=Demand) >nul 2>&1
SC Query "PrintDeviceConfigurationService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "PrintDeviceConfigurationService" Start=Demand) >nul 2>&1
SC Query "PrintDeviceConfigurationService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "PrintDeviceConfigurationService_*" Start=Demand) >nul 2>&1
SC Query "PrintNotify" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "PrintNotify" Start=Demand) >nul 2>&1
SC Query "PrintNotify_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "PrintNotify_*" Start=Demand) >nul 2>&1
SC Query "PrintScanBrokerService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "PrintScanBrokerService" Start=Demand) >nul 2>&1
SC Query "PrintScanBrokerService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "PrintScanBrokerService_*" Start=Demand) >nul 2>&1
SC Query "PrintWorkflowUserSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "PrintWorkflowUserSvc" Start=Demand) >nul 2>&1
SC Query "PrintWorkflowUserSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "PrintWorkflowUserSvc_*" Start=Demand) >nul 2>&1
SC Query "PushToInstall" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "PushToInstall" Start=Demand) >nul 2>&1
SC Query "PushToInstall_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "PushToInstall_*" Start=Demand) >nul 2>&1
SC Query "QWAVE" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "QWAVE" Start=Demand) >nul 2>&1
SC Query "QWAVE_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "QWAVE_*" Start=Demand) >nul 2>&1
SC Query "RasAuto" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "RasAuto" Start=Demand) >nul 2>&1
SC Query "RasAuto_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "RasAuto_*" Start=Demand) >nul 2>&1
SC Query "RasMan" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "RasMan" Start=Demand) >nul 2>&1
SC Query "RasMan_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "RasMan_*" Start=Demand) >nul 2>&1
SC Query "RetailDemo" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "RetailDemo" Start=Demand) >nul 2>&1
SC Query "RetailDemo_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "RetailDemo_*" Start=Demand) >nul 2>&1
SC Query "RmSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "RmSvc" Start=Demand) >nul 2>&1
SC Query "RmSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "RmSvc_*" Start=Demand) >nul 2>&1
SC Query "RpcLocator" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "RpcLocator" Start=Demand) >nul 2>&1
SC Query "RpcLocator_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "RpcLocator_*" Start=Demand) >nul 2>&1
SC Query "SCPolicySvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "SCPolicySvc" Start=Demand) >nul 2>&1
SC Query "SCPolicySvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "SCPolicySvc_*" Start=Demand) >nul 2>&1
SC Query "SCardSvr" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "SCardSvr" Start=Demand) >nul 2>&1
SC Query "SCardSvr_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "SCardSvr_*" Start=Demand) >nul 2>&1
SC Query "SDRSVC" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "SDRSVC" Start=Demand) >nul 2>&1
SC Query "SDRSVC_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "SDRSVC_*" Start=Demand) >nul 2>&1
SC Query "SEMgrSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "SEMgrSvc" Start=Demand) >nul 2>&1
SC Query "SEMgrSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "SEMgrSvc_*" Start=Demand) >nul 2>&1
SC Query "SNMPTRAP" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "SNMPTRAP" Start=Demand) >nul 2>&1
SC Query "SNMPTRAP_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "SNMPTRAP_*" Start=Demand) >nul 2>&1
SC Query "SSDPSRV" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "SSDPSRV" Start=Demand) >nul 2>&1
SC Query "SSDPSRV_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "SSDPSRV_*" Start=Demand) >nul 2>&1
SC Query "ScDeviceEnum" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "ScDeviceEnum" Start=Demand) >nul 2>&1
SC Query "ScDeviceEnum_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "ScDeviceEnum_*" Start=Demand) >nul 2>&1
SC Query "SensorService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "SensorService" Start=Demand) >nul 2>&1
SC Query "SensorService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "SensorService_*" Start=Demand) >nul 2>&1
SC Query "SensrSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "SensrSvc" Start=Demand) >nul 2>&1
SC Query "SensrSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "SensrSvc_*" Start=Demand) >nul 2>&1
SC Query "SessionEnv" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "SessionEnv" Start=Demand) >nul 2>&1
SC Query "SessionEnv_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "SessionEnv_*" Start=Demand) >nul 2>&1
SC Query "SharedAccess" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "SharedAccess" Start=Demand) >nul 2>&1
SC Query "SharedAccess_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "SharedAccess_*" Start=Demand) >nul 2>&1
SC Query "SharedRealitySvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "SharedRealitySvc" Start=Demand) >nul 2>&1
SC Query "SharedRealitySvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "SharedRealitySvc_*" Start=Demand) >nul 2>&1
SC Query "ShellHWDetection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "ShellHWDetection" Start=Demand) >nul 2>&1
SC Query "ShellHWDetection_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "ShellHWDetection_*" Start=Demand) >nul 2>&1
SC Query "SmsRouter" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "SmsRouter" Start=Demand) >nul 2>&1
SC Query "SmsRouter_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "SmsRouter_*" Start=Demand) >nul 2>&1
SC Query "Spooler" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "Spooler" Start=Demand) >nul 2>&1
SC Query "Spooler_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "Spooler_*" Start=Demand) >nul 2>&1
SC Query "SstpSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "SstpSvc" Start=Demand) >nul 2>&1
SC Query "SstpSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "SstpSvc_*" Start=Demand) >nul 2>&1
SC Query "StiSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "StiSvc" Start=Demand) >nul 2>&1
SC Query "StiSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "StiSvc_*" Start=Demand) >nul 2>&1
SC Query "StorSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "StorSvc" Start=Demand) >nul 2>&1
SC Query "StorSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "StorSvc_*" Start=Demand) >nul 2>&1
SC Query "TabletInputService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "TabletInputService" Start=Demand) >nul 2>&1
SC Query "TabletInputService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "TabletInputService_*" Start=Demand) >nul 2>&1
SC Query "TapiSrv" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "TapiSrv" Start=Demand) >nul 2>&1
SC Query "TapiSrv_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "TapiSrv_*" Start=Demand) >nul 2>&1
SC Query "TermService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "TermService" Start=Demand) >nul 2>&1
SC Query "TermService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "TermService_*" Start=Demand) >nul 2>&1
SC Query "Themes" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "Themes" Start=Demand) >nul 2>&1
SC Query "Themes_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "Themes_*" Start=Demand) >nul 2>&1
SC Query "TieringEngineService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "TieringEngineService" Start=Demand) >nul 2>&1
SC Query "TieringEngineService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "TieringEngineService_*" Start=Demand) >nul 2>&1
SC Query "TimeBroker" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "TimeBroker" Start=Demand) >nul 2>&1
SC Query "TimeBrokerSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "TimeBrokerSvc" Start=Demand) >nul 2>&1
SC Query "TimeBrokerSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "TimeBrokerSvc_*" Start=Demand) >nul 2>&1
SC Query "TimeBroker_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "TimeBroker_*" Start=Demand) >nul 2>&1
SC Query "TokenBroker" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "TokenBroker" Start=Demand) >nul 2>&1
SC Query "TokenBroker_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "TokenBroker_*" Start=Demand) >nul 2>&1
SC Query "TroubleshootingSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "TroubleshootingSvc" Start=Demand) >nul 2>&1
SC Query "TroubleshootingSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "TroubleshootingSvc_*" Start=Demand) >nul 2>&1
SC Query "UI0Detect" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "UI0Detect" Start=Demand) >nul 2>&1
SC Query "UI0Detect_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "UI0Detect_*" Start=Demand) >nul 2>&1
SC Query "UdkUserSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "UdkUserSvc" Start=Demand) >nul 2>&1
SC Query "UdkUserSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "UdkUserSvc_*" Start=Demand) >nul 2>&1
SC Query "UmRdpService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "UmRdpService" Start=Demand) >nul 2>&1
SC Query "UmRdpService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "UmRdpService_*" Start=Demand) >nul 2>&1
SC Query "UnistoreSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "UnistoreSvc" Start=Demand) >nul 2>&1
SC Query "UnistoreSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "UnistoreSvc_*" Start=Demand) >nul 2>&1
SC Query "UserDataSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "UserDataSvc" Start=Demand) >nul 2>&1
SC Query "UserDataSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "UserDataSvc_*" Start=Demand) >nul 2>&1
SC Query "UsoSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "UsoSvc" Start=Demand) >nul 2>&1
SC Query "UsoSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "UsoSvc_*" Start=Demand) >nul 2>&1
SC Query "VSS" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "VSS" Start=Demand) >nul 2>&1
SC Query "VSS_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "VSS_*" Start=Demand) >nul 2>&1
SC Query "VacSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "VacSvc" Start=Demand) >nul 2>&1
SC Query "VacSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "VacSvc_*" Start=Demand) >nul 2>&1
SC Query "VaultSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "VaultSvc" Start=Demand) >nul 2>&1
SC Query "VaultSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "VaultSvc_*" Start=Demand) >nul 2>&1
SC Query "W32Time" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "W32Time" Start=Demand) >nul 2>&1
SC Query "W32Time_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "W32Time_*" Start=Demand) >nul 2>&1
SC Query "WEPHOSTSVC" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WEPHOSTSVC" Start=Demand) >nul 2>&1
SC Query "WEPHOSTSVC_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WEPHOSTSVC_*" Start=Demand) >nul 2>&1
SC Query "WFDSConMgrSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WFDSConMgrSvc" Start=Demand) >nul 2>&1
SC Query "WFDSConMgrSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WFDSConMgrSvc_*" Start=Demand) >nul 2>&1
SC Query "WManSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WManSvc" Start=Demand) >nul 2>&1
SC Query "WManSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WManSvc_*" Start=Demand) >nul 2>&1
SC Query "WPDBusEnum" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WPDBusEnum" Start=Demand) >nul 2>&1
SC Query "WPDBusEnum_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WPDBusEnum_*" Start=Demand) >nul 2>&1
SC Query "WSService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WSService" Start=Demand) >nul 2>&1
SC Query "WSService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WSService_*" Start=Demand) >nul 2>&1
SC Query "WaaSMedicSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WaaSMedicSvc" Start=Demand) >nul 2>&1
SC Query "WaaSMedicSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WaaSMedicSvc_*" Start=Demand) >nul 2>&1
SC Query "WalletService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WalletService" Start=Demand) >nul 2>&1
SC Query "WalletService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WalletService_*" Start=Demand) >nul 2>&1
SC Query "WarpJITSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WarpJITSvc" Start=Demand) >nul 2>&1
SC Query "WarpJITSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WarpJITSvc_*" Start=Demand) >nul 2>&1
SC Query "WbioSrvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WbioSrvc" Start=Demand) >nul 2>&1
SC Query "WbioSrvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WbioSrvc_*" Start=Demand) >nul 2>&1
SC Query "WcsPlugInService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WcsPlugInService" Start=Demand) >nul 2>&1
SC Query "WcsPlugInService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WcsPlugInService_*" Start=Demand) >nul 2>&1
SC Query "WdNisSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WdNisSvc" Start=Demand) >nul 2>&1
SC Query "WdNisSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WdNisSvc_*" Start=Demand) >nul 2>&1
SC Query "WdiServiceHost" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WdiServiceHost" Start=Demand) >nul 2>&1
SC Query "WdiServiceHost_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WdiServiceHost_*" Start=Demand) >nul 2>&1
SC Query "WdiSystemHost" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WdiSystemHost" Start=Demand) >nul 2>&1
SC Query "WdiSystemHost_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WdiSystemHost_*" Start=Demand) >nul 2>&1
SC Query "WebClient" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WebClient" Start=Demand) >nul 2>&1
SC Query "WebClient_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WebClient_*" Start=Demand) >nul 2>&1
SC Query "Wecsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "Wecsvc" Start=Demand) >nul 2>&1
SC Query "Wecsvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "Wecsvc_*" Start=Demand) >nul 2>&1
SC Query "WiaRpc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WiaRpc" Start=Demand) >nul 2>&1
SC Query "WiaRpc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WiaRpc_*" Start=Demand) >nul 2>&1
SC Query "WinHttpAutoProxySvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WinHttpAutoProxySvc" Start=Demand) >nul 2>&1
SC Query "WinHttpAutoProxySvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WinHttpAutoProxySvc_*" Start=Demand) >nul 2>&1
SC Query "WinRM" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WinRM" Start=Demand) >nul 2>&1
SC Query "WinRM_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WinRM_*" Start=Demand) >nul 2>&1
SC Query "WlanSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WlanSvc" Start=Demand) >nul 2>&1
SC Query "WlanSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WlanSvc_*" Start=Demand) >nul 2>&1
SC Query "WpcMonSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WpcMonSvc" Start=Demand) >nul 2>&1
SC Query "WpcMonSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WpcMonSvc_*" Start=Demand) >nul 2>&1
SC Query "WpnService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WpnService" Start=Demand) >nul 2>&1
SC Query "WpnService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WpnService_*" Start=Demand) >nul 2>&1
SC Query "WwanSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WwanSvc" Start=Demand) >nul 2>&1
SC Query "WwanSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "WwanSvc_*" Start=Demand) >nul 2>&1
SC Query "ZTHELPER" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "ZTHELPER" Start=Demand) >nul 2>&1
SC Query "ZTHELPER_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "ZTHELPER_*" Start=Demand) >nul 2>&1
SC Query "autotimesvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "autotimesvc" Start=Demand) >nul 2>&1
SC Query "autotimesvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "autotimesvc_*" Start=Demand) >nul 2>&1
SC Query "bthserv" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "bthserv" Start=Demand) >nul 2>&1
SC Query "bthserv_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "bthserv_*" Start=Demand) >nul 2>&1
SC Query "camsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "camsvc" Start=Demand) >nul 2>&1
SC Query "camsvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "camsvc_*" Start=Demand) >nul 2>&1
SC Query "cbdhsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "cbdhsvc" Start=Demand) >nul 2>&1
SC Query "cbdhsvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "cbdhsvc_*" Start=Demand) >nul 2>&1
SC Query "cloudidsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "cloudidsvc" Start=Demand) >nul 2>&1
SC Query "cloudidsvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "cloudidsvc_*" Start=Demand) >nul 2>&1
SC Query "dcsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "dcsvc" Start=Demand) >nul 2>&1
SC Query "dcsvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "dcsvc_*" Start=Demand) >nul 2>&1
SC Query "defragsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "defragsvc" Start=Demand) >nul 2>&1
SC Query "defragsvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "defragsvc_*" Start=Demand) >nul 2>&1
SC Query "diagnosticshub.standardcollector.service" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "diagnosticshub.standardcollector.service" Start=Demand) >nul 2>&1
SC Query "diagnosticshub.standardcollector.service_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "diagnosticshub.standardcollector.service_*" Start=Demand) >nul 2>&1
SC Query "diagsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "diagsvc" Start=Demand) >nul 2>&1
SC Query "diagsvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "diagsvc_*" Start=Demand) >nul 2>&1
SC Query "dmwappushservice" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "dmwappushservice" Start=Demand) >nul 2>&1
SC Query "dmwappushservice_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "dmwappushservice_*" Start=Demand) >nul 2>&1
SC Query "dot3svc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "dot3svc" Start=Demand) >nul 2>&1
SC Query "dot3svc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "dot3svc_*" Start=Demand) >nul 2>&1
SC Query "edgeupdate" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "edgeupdate" Start=Demand) >nul 2>&1
SC Query "edgeupdate_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "edgeupdate_*" Start=Demand) >nul 2>&1
SC Query "edgeupdatem" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "edgeupdatem" Start=Demand) >nul 2>&1
SC Query "edgeupdatem_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "edgeupdatem_*" Start=Demand) >nul 2>&1
SC Query "embeddedmode" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "embeddedmode" Start=Demand) >nul 2>&1
SC Query "embeddedmode_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "embeddedmode_*" Start=Demand) >nul 2>&1
SC Query "fdPHost" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "fdPHost" Start=Demand) >nul 2>&1
SC Query "fdPHost_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "fdPHost_*" Start=Demand) >nul 2>&1
SC Query "fhsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "fhsvc" Start=Demand) >nul 2>&1
SC Query "fhsvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "fhsvc_*" Start=Demand) >nul 2>&1
SC Query "hidserv" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "hidserv" Start=Demand) >nul 2>&1
SC Query "hidserv_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "hidserv_*" Start=Demand) >nul 2>&1
SC Query "hpatchmon" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "hpatchmon" Start=Demand) >nul 2>&1
SC Query "hpatchmon_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "hpatchmon_*" Start=Demand) >nul 2>&1
SC Query "icssvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "icssvc" Start=Demand) >nul 2>&1
SC Query "icssvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "icssvc_*" Start=Demand) >nul 2>&1
SC Query "lfsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "lfsvc" Start=Demand) >nul 2>&1
SC Query "lfsvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "lfsvc_*" Start=Demand) >nul 2>&1
SC Query "lltdsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "lltdsvc" Start=Demand) >nul 2>&1
SC Query "lltdsvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "lltdsvc_*" Start=Demand) >nul 2>&1
SC Query "lmhosts" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "lmhosts" Start=Demand) >nul 2>&1
SC Query "lmhosts_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "lmhosts_*" Start=Demand) >nul 2>&1
SC Query "msiserver" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "msiserver" Start=Demand) >nul 2>&1
SC Query "msiserver_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "msiserver_*" Start=Demand) >nul 2>&1
SC Query "netprofm" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "netprofm" Start=Demand) >nul 2>&1
SC Query "netprofm_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "netprofm_*" Start=Demand) >nul 2>&1
SC Query "p2pimsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "p2pimsvc" Start=Demand) >nul 2>&1
SC Query "p2pimsvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "p2pimsvc_*" Start=Demand) >nul 2>&1
SC Query "p2psvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "p2psvc" Start=Demand) >nul 2>&1
SC Query "p2psvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "p2psvc_*" Start=Demand) >nul 2>&1
SC Query "perceptionsimulation" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "perceptionsimulation" Start=Demand) >nul 2>&1
SC Query "perceptionsimulation_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "perceptionsimulation_*" Start=Demand) >nul 2>&1
SC Query "pla" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "pla" Start=Demand) >nul 2>&1
SC Query "pla_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "pla_*" Start=Demand) >nul 2>&1
SC Query "refsdedupsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "refsdedupsvc" Start=Demand) >nul 2>&1
SC Query "refsdedupsvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "refsdedupsvc_*" Start=Demand) >nul 2>&1
SC Query "seclogon" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "seclogon" Start=Demand) >nul 2>&1
SC Query "seclogon_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "seclogon_*" Start=Demand) >nul 2>&1
SC Query "smphost" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "smphost" Start=Demand) >nul 2>&1
SC Query "smphost_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "smphost_*" Start=Demand) >nul 2>&1
SC Query "spectrum" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "spectrum" Start=Demand) >nul 2>&1
SC Query "spectrum_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "spectrum_*" Start=Demand) >nul 2>&1
SC Query "svsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "svsvc" Start=Demand) >nul 2>&1
SC Query "svsvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "svsvc_*" Start=Demand) >nul 2>&1
SC Query "swprv" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "swprv" Start=Demand) >nul 2>&1
SC Query "swprv_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "swprv_*" Start=Demand) >nul 2>&1
SC Query "uhssvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "uhssvc" Start=Demand) >nul 2>&1
SC Query "uhssvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "uhssvc_*" Start=Demand) >nul 2>&1
SC Query "upnphost" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "upnphost" Start=Demand) >nul 2>&1
SC Query "upnphost_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "upnphost_*" Start=Demand) >nul 2>&1
SC Query "vds" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "vds" Start=Demand) >nul 2>&1
SC Query "vds_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "vds_*" Start=Demand) >nul 2>&1
SC Query "vm3dservice" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "vm3dservice" Start=Demand) >nul 2>&1
SC Query "vm3dservice_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "vm3dservice_*" Start=Demand) >nul 2>&1
SC Query "vmicguestinterface" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "vmicguestinterface" Start=Demand) >nul 2>&1
SC Query "vmicguestinterface_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "vmicguestinterface_*" Start=Demand) >nul 2>&1
SC Query "vmicheartbeat" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "vmicheartbeat" Start=Demand) >nul 2>&1
SC Query "vmicheartbeat_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "vmicheartbeat_*" Start=Demand) >nul 2>&1
SC Query "vmickvpexchange" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "vmickvpexchange" Start=Demand) >nul 2>&1
SC Query "vmickvpexchange_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "vmickvpexchange_*" Start=Demand) >nul 2>&1
SC Query "vmicrdv" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "vmicrdv" Start=Demand) >nul 2>&1
SC Query "vmicrdv_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "vmicrdv_*" Start=Demand) >nul 2>&1
SC Query "vmicshutdown" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "vmicshutdown" Start=Demand) >nul 2>&1
SC Query "vmicshutdown_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "vmicshutdown_*" Start=Demand) >nul 2>&1
SC Query "vmictimesync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "vmictimesync" Start=Demand) >nul 2>&1
SC Query "vmictimesync_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "vmictimesync_*" Start=Demand) >nul 2>&1
SC Query "vmicvmsession" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "vmicvmsession" Start=Demand) >nul 2>&1
SC Query "vmicvmsession_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "vmicvmsession_*" Start=Demand) >nul 2>&1
SC Query "vmicvss" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "vmicvss" Start=Demand) >nul 2>&1
SC Query "vmicvss_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "vmicvss_*" Start=Demand) >nul 2>&1
SC Query "vmvss" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "vmvss" Start=Demand) >nul 2>&1
SC Query "vmvss_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "vmvss_*" Start=Demand) >nul 2>&1
SC Query "wbengine" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "wbengine" Start=Demand) >nul 2>&1
SC Query "wbengine_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "wbengine_*" Start=Demand) >nul 2>&1
SC Query "wcncsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "wcncsvc" Start=Demand) >nul 2>&1
SC Query "wcncsvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "wcncsvc_*" Start=Demand) >nul 2>&1
SC Query "wercplsupport" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "wercplsupport" Start=Demand) >nul 2>&1
SC Query "wercplsupport_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "wercplsupport_*" Start=Demand) >nul 2>&1
SC Query "whesvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "whesvc" Start=Demand) >nul 2>&1
SC Query "whesvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "whesvc_*" Start=Demand) >nul 2>&1
SC Query "wisvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "wisvc" Start=Demand) >nul 2>&1
SC Query "wisvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "wisvc_*" Start=Demand) >nul 2>&1
SC Query "wlidsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "wlidsvc" Start=Demand) >nul 2>&1
SC Query "wlidsvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "wlidsvc_*" Start=Demand) >nul 2>&1
SC Query "wlpasvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "wlpasvc" Start=Demand) >nul 2>&1
SC Query "wlpasvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "wlpasvc_*" Start=Demand) >nul 2>&1
SC Query "wmiApSrv" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "wmiApSrv" Start=Demand) >nul 2>&1
SC Query "wmiApSrv_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "wmiApSrv_*" Start=Demand) >nul 2>&1
SC Query "wscsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "wscsvc" Start=Demand) >nul 2>&1
SC Query "wscsvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "wscsvc_*" Start=Demand) >nul 2>&1
SC Query "wuauserv" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "wuauserv" Start=Demand) >nul 2>&1
SC Query "wuauserv_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "wuauserv_*" Start=Demand) >nul 2>&1
SC Query "wudfsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "wudfsvc" Start=Demand) >nul 2>&1
SC Query "wudfsvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (SC Config "wudfsvc_*" Start=Demand) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\ALG" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ALG" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AarSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AarSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AppIDSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AppIDSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AppMgmt" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AppMgmt" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AppReadiness" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AppReadiness" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AppXSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AppXSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Appinfo" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Appinfo" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\ApxSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ApxSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AssignedAccessManagerSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AssignedAccessManagerSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AxInstSV" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AxInstSV" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\BDESVC" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\BDESVC" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\BITS" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\BITS" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\BTAGService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\BTAGService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\BluetoothUserService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\BluetoothUserService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Browser" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Browser" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\BthAvctpSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\BthAvctpSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\CDPSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CDPSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\CDPUserSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CDPUserSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\COMSysApp" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\COMSysApp" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\CaptureService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CaptureService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\CertPropSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CertPropSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\ClipSVC" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ClipSVC" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\CloudBackupRestoreSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CloudBackupRestoreSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\CscService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CscService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DPS" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DPS" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DcpSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DcpSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DevQueryBroker" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DevQueryBroker" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DeviceAssociationService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DeviceAssociationService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DeviceInstall" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DeviceInstall" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DisplayEnhancementService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DisplayEnhancementService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DmEnrollmentSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DmEnrollmentSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DoSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DoSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DsSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DsSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DsmSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DsmSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DusmSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DusmSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\EFS" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\EFS" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\EapHost" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\EapHost" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\EntAppSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\EntAppSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\FDResPub" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\FDResPub" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\FontCache" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\FontCache" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\FrameServer" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\FrameServer" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\FrameServerMonitor" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\FrameServerMonitor" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\GameInputSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\GameInputSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupListener" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupListener" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupProvider" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupProvider" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\HvHost" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\HvHost" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\IEEtwCollectorService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\IEEtwCollectorService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\InstallService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\InstallService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\InventorySvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\InventorySvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\IpxlatCfgSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\IpxlatCfgSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\KeyIso" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\KeyIso" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\KtmRm" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\KtmRm" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\LicenseManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\LicenseManager" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\LocalKdc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\LocalKdc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\LxpSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\LxpSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\MSDTC" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MSDTC" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\MSiSCSI" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MSiSCSI" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\MapsBroker" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MapsBroker" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\McmSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\McmSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\McpManagementService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\McpManagementService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\MessagingService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MessagingService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NPSMSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NPSMSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NaturalAuthentication" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NaturalAuthentication" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NcaSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NcaSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NcbService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NcbService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NcdAutoSetup" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NcdAutoSetup" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NetSetupSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NetSetupSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Netman" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Netman" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NgcCtnrSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NgcCtnrSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NgcSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NgcSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PNRPAutoREG" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PNRPAutoREG" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PNRPsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PNRPsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PcaSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PcaSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PeerDistSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PeerDistSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PenService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PenService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PerfHost" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PerfHost" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PhoneSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PhoneSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PlugPlay" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PlugPlay" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgent" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgent" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PrintDeviceConfigurationService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PrintDeviceConfigurationService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PrintNotify" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PrintNotify" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PrintScanBrokerService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PrintScanBrokerService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PushToInstall" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PushToInstall" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\QWAVE" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\QWAVE" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\RasAuto" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RasAuto" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\RasMan" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RasMan" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\RetailDemo" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RetailDemo" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\RmSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RmSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\RpcLocator" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RpcLocator" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SCPolicySvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SCPolicySvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SCardSvr" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SCardSvr" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SDRSVC" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SDRSVC" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SEMgrSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SEMgrSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SNMPTRAP" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SNMPTRAP" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SSDPSRV" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SSDPSRV" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\ScDeviceEnum" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ScDeviceEnum" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SensorService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SensorService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SensrSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SensrSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SessionEnv" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SessionEnv" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SharedRealitySvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SharedRealitySvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\ShellHWDetection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ShellHWDetection" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SmsRouter" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SmsRouter" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SstpSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SstpSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\StiSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\StiSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\StorSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\StorSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\TabletInputService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TabletInputService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\TapiSrv" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TapiSrv" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\TermService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TermService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Themes" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Themes" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\TieringEngineService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TieringEngineService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\TimeBroker" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TimeBroker" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\TokenBroker" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TokenBroker" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\TroubleshootingSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TroubleshootingSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\UI0Detect" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UI0Detect" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\UdkUserSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UdkUserSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\UmRdpService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UmRdpService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\UnistoreSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UnistoreSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\UserDataSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UserDataSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\UsoSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UsoSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\VSS" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\VSS" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\VacSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\VacSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\VaultSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\VaultSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\W32Time" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\W32Time" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WEPHOSTSVC" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WEPHOSTSVC" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WFDSConMgrSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WFDSConMgrSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WManSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WManSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WPDBusEnum" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WPDBusEnum" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WSService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WSService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WalletService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WalletService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WarpJITSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WarpJITSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WbioSrvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WbioSrvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WcsPlugInService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WcsPlugInService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WdiServiceHost" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WdiServiceHost" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WdiSystemHost" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WdiSystemHost" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WebClient" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WebClient" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Wecsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Wecsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WiaRpc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WinRM" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WinRM" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WlanSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WlanSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WpcMonSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WpcMonSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WpnService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WpnService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WwanSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WwanSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\ZTHELPER" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ZTHELPER" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\autotimesvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\autotimesvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\bthserv" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\bthserv" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\camsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\camsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\cbdhsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\cbdhsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\cloudidsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\cloudidsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\dcsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\dcsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\defragsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\defragsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\diagsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\diagsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\dot3svc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\dot3svc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdate" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdate" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdatem" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdatem" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\embeddedmode" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\embeddedmode" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\fdPHost" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\fdPHost" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\fhsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\fhsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\hidserv" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\hidserv" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\hpatchmon" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\hpatchmon" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\icssvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\icssvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\lltdsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\lltdsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\lmhosts" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\lmhosts" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\msiserver" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\msiserver" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\netprofm" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\netprofm" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\p2pimsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\p2pimsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\p2psvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\p2psvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\perceptionsimulation" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\perceptionsimulation" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\pla" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\pla" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\refsdedupsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\refsdedupsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\seclogon" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\seclogon" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\smphost" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\smphost" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\spectrum" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\spectrum" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\svsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\svsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\swprv" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\swprv" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\uhssvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\uhssvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\upnphost" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\upnphost" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vds" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vds" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vm3dservice" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vm3dservice" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmicguestinterface" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmicguestinterface" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmicheartbeat" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmicheartbeat" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmickvpexchange" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmickvpexchange" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmicrdv" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmicrdv" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmicshutdown" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmicshutdown" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmictimesync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmictimesync" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmicvmsession" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmicvmsession" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmicvss" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmicvss" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmvss" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmvss" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wbengine" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wbengine" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wcncsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wcncsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wercplsupport" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wercplsupport" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\whesvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\whesvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wisvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wisvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wlidsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wlidsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wlpasvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wlpasvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wmiApSrv" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wmiApSrv" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wscsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wscsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wuauserv" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wuauserv" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wudfsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wudfsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\ALGـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ALGـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AarSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AarSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AppIDSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AppIDSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AppMgmtـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AppMgmtـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AppReadinessـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AppReadinessـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AppXSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AppXSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Appinfoـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Appinfoـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\ApxSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ApxSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AssignedAccessManagerSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AssignedAccessManagerSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\AxInstSVـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\AxInstSVـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\BDESVCـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\BDESVCـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\BITSـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\BITSـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\BTAGServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\BTAGServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\BluetoothUserServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\BluetoothUserServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Browserـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Browserـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\BthAvctpSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\BthAvctpSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\CDPSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CDPSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\CDPUserSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CDPUserSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\COMSysAppـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\COMSysAppـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\CaptureServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CaptureServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\CertPropSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CertPropSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\ClipSVCـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ClipSVCـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\CloudBackupRestoreSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CloudBackupRestoreSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\CscServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\CscServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DPSـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DPSـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DcpSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DcpSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DevQueryBrokerـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DevQueryBrokerـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DeviceAssociationServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DeviceAssociationServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DeviceInstallـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DeviceInstallـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrackـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrackـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DisplayEnhancementServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DisplayEnhancementServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DmEnrollmentSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DmEnrollmentSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DoSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DoSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DsSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DsSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DsmSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DsmSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\DusmSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\DusmSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\EFSـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\EFSـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\EapHostـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\EapHostـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\EntAppSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\EntAppSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\FDResPubـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\FDResPubـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\FontCacheـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\FontCacheـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\FrameServerـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\FrameServerـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\FrameServerMonitorـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\FrameServerMonitorـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\GameInputSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\GameInputSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupListenerـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupListenerـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupProviderـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupProviderـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\HvHostـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\HvHostـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\IEEtwCollectorServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\IEEtwCollectorServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\InstallServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\InstallServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\InventorySvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\InventorySvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\IpxlatCfgSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\IpxlatCfgSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\KeyIsoـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\KeyIsoـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\KtmRmـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\KtmRmـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\LicenseManagerـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\LicenseManagerـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\LocalKdcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\LocalKdcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\LxpSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\LxpSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\MSDTCـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MSDTCـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\MSiSCSIـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MSiSCSIـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\MapsBrokerـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MapsBrokerـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\McmSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\McmSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\McpManagementServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\McpManagementServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\MessagingServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MessagingServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NPSMSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NPSMSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NaturalAuthenticationـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NaturalAuthenticationـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NcaSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NcaSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NcbServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NcbServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NcdAutoSetupـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NcdAutoSetupـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NetSetupSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NetSetupSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Netlogonـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogonـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Netmanـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Netmanـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NgcCtnrSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NgcCtnrSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NgcSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NgcSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PNRPAutoREGـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PNRPAutoREGـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PNRPsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PNRPsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PcaSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PcaSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PeerDistSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PeerDistSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PenServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PenServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PerfHostـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PerfHostـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PhoneSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PhoneSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PlugPlayـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PlugPlayـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgentـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgentـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PrintDeviceConfigurationServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PrintDeviceConfigurationServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PrintNotifyـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PrintNotifyـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PrintScanBrokerServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PrintScanBrokerServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\PushToInstallـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\PushToInstallـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\QWAVEـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\QWAVEـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\RasAutoـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RasAutoـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\RasManـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RasManـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\RetailDemoـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RetailDemoـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\RmSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RmSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\RpcLocatorـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\RpcLocatorـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SCPolicySvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SCPolicySvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SCardSvrـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SCardSvrـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SDRSVCـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SDRSVCـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SEMgrSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SEMgrSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SNMPTRAPـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SNMPTRAPـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SSDPSRVـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SSDPSRVـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\ScDeviceEnumـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ScDeviceEnumـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SensorServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SensorServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SensrSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SensrSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SessionEnvـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SessionEnvـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccessـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccessـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SharedRealitySvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SharedRealitySvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\ShellHWDetectionـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ShellHWDetectionـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SmsRouterـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SmsRouterـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Spoolerـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Spoolerـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\SstpSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\SstpSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\StiSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\StiSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\StorSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\StorSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\TabletInputServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TabletInputServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\TapiSrvـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TapiSrvـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\TermServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TermServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Themesـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Themesـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\TieringEngineServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TieringEngineServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\TimeBrokerـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TimeBrokerـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\TimeBrokerSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TimeBrokerSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\TokenBrokerـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TokenBrokerـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\TroubleshootingSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\TroubleshootingSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\UI0Detectـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UI0Detectـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\UdkUserSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UdkUserSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\UmRdpServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UmRdpServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\UnistoreSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UnistoreSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\UserDataSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UserDataSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\UsoSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\UsoSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\VSSـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\VSSـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\VacSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\VacSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\VaultSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\VaultSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\W32Timeـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\W32Timeـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WEPHOSTSVCـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WEPHOSTSVCـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WFDSConMgrSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WFDSConMgrSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WManSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WManSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WPDBusEnumـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WPDBusEnumـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WSServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WSServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WalletServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WalletServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WarpJITSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WarpJITSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WbioSrvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WbioSrvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WcsPlugInServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WcsPlugInServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WdiServiceHostـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WdiServiceHostـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WdiSystemHostـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WdiSystemHostـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WebClientـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WebClientـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\Wecsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\Wecsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WiaRpcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WinRMـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WinRMـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WlanSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WlanSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WpcMonSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WpcMonSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WpnServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WpnServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\WwanSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\WwanSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\ZTHELPERـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\ZTHELPERـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\autotimesvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\autotimesvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\bthservـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\bthservـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\camsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\camsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\cbdhsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\cbdhsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\cloudidsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\cloudidsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\dcsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\dcsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\defragsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\defragsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.serviceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.serviceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\diagsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\diagsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushserviceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushserviceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\dot3svcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\dot3svcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdateـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdateـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdatemـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdatemـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\embeddedmodeـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\embeddedmodeـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\fdPHostـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\fdPHostـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\fhsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\fhsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\hidservـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\hidservـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\hpatchmonـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\hpatchmonـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\icssvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\icssvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\lfsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\lltdsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\lltdsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\lmhostsـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\lmhostsـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\msiserverـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\msiserverـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\netprofmـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\netprofmـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\p2pimsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\p2pimsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\p2psvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\p2psvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\perceptionsimulationـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\perceptionsimulationـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\plaـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\plaـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\refsdedupsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\refsdedupsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\seclogonـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\seclogonـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\smphostـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\smphostـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\spectrumـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\spectrumـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\svsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\svsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\swprvـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\swprvـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\uhssvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\uhssvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\upnphostـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\upnphostـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vdsـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vdsـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vm3dserviceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vm3dserviceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmicguestinterfaceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmicguestinterfaceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmicheartbeatـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmicheartbeatـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmickvpexchangeـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmickvpexchangeـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmicrdvـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmicrdvـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmicshutdownـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmicshutdownـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmictimesyncـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmictimesyncـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmicvmsessionـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmicvmsessionـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmicvssـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmicvssـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\vmvssـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\vmvssـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wbengineـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wbengineـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wcncsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wcncsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wercplsupportـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wercplsupportـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\whesvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\whesvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wisvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wisvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wlidsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wlidsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wlpasvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wlpasvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wmiApSrvـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wmiApSrvـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wscsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wscsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wuauservـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wuauservـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKLM\SYSTEM\CurrentControlSet\Services\wudfsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKLM\SYSTEM\CurrentControlSet\Services\wudfsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1

ECHO.
ECHO Done.


ECHO.
ECHO :::::::::::::::::::::::::::::::::::::
ECHO ::::: Disabling Scheduled Tasks :::::
ECHO :::::::::::::::::::::::::::::::::::::
ECHO.

SchTasks /Change /TN "MicrosoftEdgeUpdateTaskMachineCore" /Disable >nul 2>&1
SchTasks /Change /TN "MicrosoftEdgeUpdateTaskMachineUA" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Office/OfficeTelemetryAgentFallBack" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Office/OfficeTelemetryAgentLogOn" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\.NET Framework/.NET Framework NGEN v4.0.30319 64 Critical" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\.NET Framework/.NET Framework NGEN v4.0.30319 Critical" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\AccountHealth\RecoverabilityToastTask" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Application Experience/Microsoft Compatibility Appraiser Exp" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Application Experience/Microsoft Compatibility Appraiser" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Application Experience/StartupAppTask" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Application Experience\MareBackup" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Application Experience\PcaPatchDbTask" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Application Experience\SdbinstMergeDbTask" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\BitLocker/BitLocker Encrypt All Drives" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\BitLocker/BitLocker MDM policy Refresh" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\BitLocker\BitLocker Encrypt All Drives" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\BitLocker\BitLocker MDM policy Refresh" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\CloudRestore/Backup" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\CloudRestore/Restore" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\CloudRestore\Backup" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\CloudRestore\Restore" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program/Consolidator" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\DUSM\dusmtask" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Device Information\Device User" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Device Information\Device" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Diagnosis\Scheduled" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Diagnosis\UnexpectedCodePath" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\DiskCleanup\SilentCleanup" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\DiskFootprint\StorageSense" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\remoteAssistance\remoteAssistanceTask" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\EnterpriseMgmt\MDMMaintenenceTask" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuaRD MDM policy Refresh" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\FileHistory/File History (maintenance mode)" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\ReconcileFeatures" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataFlushing" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataReporting" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Flighting\OneSettings\RefreshCache" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Input\InputSettingsRestoreDataAvailable" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Input\LocalUserSyncDataAvailable" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Input\MouseSyncDataAvailable" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Input\PenSyncDataAvailable" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Input\RemoteMouseSyncDataAvailable" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Input\RemotePenSyncDataAvailable" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Input\RemoteTouchpadSyncDataAvailable" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Input\TouchpadSyncDataAvailable" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\International\Synchronize Language Settings" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Installation" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Uninstallation" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\MUI\LPremove" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Management\Provisioning\Cellular" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Management\Provisioning\Logon" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Maps\MapsToastTask" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Maps\MapsUpdateTask" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Multimedia\SystemSoundsService" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\NlaSvc\WiFiTask" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Printing\EduPrintProv" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Printing\PrintJobCleanupTask" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Printing\PrinterCleanupTask" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\PushToInstall\Registration" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Ras\MobilityManager" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\RecoveryEnvironment\VerifyWinRE" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\RetailDemo\CleanupOfflineContent" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Servicing\StartComponentCleanup" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\SettingSync\NetworkStateChangeTask" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Setup\SetupCleanupTask" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Setup\SnapshotCleanupTask" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefreshTask" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Shell\ThemesSyncedImageDownload" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Shell\UpdateUserPictureTask" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\SpacePort\SpaceAgentTask" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\SpacePort\SpaceManagerTask" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Speech\SpeechModelDownloadTask" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Storage Tiers Management\Storage Tiers Management Initialization" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Sysmain\ResPriStaticDbSync" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Sysmain\WsSwapAssessmentTask" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\SystemRestore\SR" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\TPM\Tpm-HASCertRetr" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\TPM\Tpm-Maintenance" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Task Manager\Interactive" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\TextServicesFramework\MsCtfMonitor" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Time Zone\SynchronizeTimeZone" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\UPnP\UPnPHostConfig" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\User Profile Service\HiveUploadTask" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\WCM\WiFiTask" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\WDI\ResolutionHost" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\WOF\WIM-Hash-Management" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\WOF\WIM-Hash-Validation" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\WindowsAI\Settings\InitialConfiguration" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\WlanSvc\CDSSync" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Logon Synchronization" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Maintenance Work" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\Workplace Join\Automatic-Device-Join" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\WwanSvc\NotificationTask" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\Windows\WwanSvc\OobeDiscovery" /Disable >nul 2>&1
SchTasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /Disable >nul 2>&1
SchTasks /Change /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable >nul 2>&1
SchTasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable >nul 2>&1 
SchTasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable >nul 2>&1
SchTasks /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable >nul 2>&1
SchTasks /Change /TN "\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents" /Disable >nul 2>&1
SchTasks /Change /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Disable >nul 2>&1
SchTasks /Change /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable >nul 2>&1

ECHO Done.


ECHO.
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO ::::: Setting Registry Keys for Current User :::::
ECHO ::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO.

REG Query "HKCU\SOFTWARE\Classes\CLSID" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" /V "System.IsPinnedToNameSpaceTree" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\Microsoft.Microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\Microsoft.Microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /V "EnabledV9" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\Microsoft.Microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Privacy" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\Microsoft.Microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Privacy" /V "EnableEncryptedMediaExtensions" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Edge\SmartScreenEnabled" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Edge\SmartScreenEnabled" /VE /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Edge\SmartScreenPuaEnabled" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Edge\SmartScreenPuaEnabled" /VE /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\InputPersonalization" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /V "RestrictImplicitInkCollection" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\InputPersonalization" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /V "RestrictImplicitTextCollection" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /V "HarvestContacts" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /V "HarvestContacts" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /V "HarvestContacts" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Input\TIPC" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Input\TIPC" /V "Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Input\TIPC" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Input\TIPC" /V "Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /V "UsageTracking" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\OneDrive" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\OneDrive" /V "DisablePersonalSync" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\OneDrive" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\OneDrive" /V "PreventNetworkTrafficPreUserSignIn" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\PCHealth\ErrorReporting" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\PCHealth\ErrorReporting" /V "DoReport" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\PCHealth\ErrorReporting" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\PCHealth\ErrorReporting" /V "ShowUI" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Personalization\Settings" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /V "AcceptedPrivacyPolicy" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Personalization\Settings" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /V "AcceptedPrivacyPolicy" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Personalization\Settings" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /V "AcceptedPrivacyPolicy" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\PolicyManager\current\device\Browser" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\PolicyManager\current\device\Browser" /V "AllowAddressBarDropdown" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\PolicyManager\current\device\Education" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\PolicyManager\current\device\Education" /V "IsEducationEnvironment" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\PolicyManager\current\device\Experience" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\PolicyManager\current\device\Experience" /V "AllowCortana" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\PolicyManager\current\device\Experience" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\PolicyManager\current\device\Experience" /V "AllowTailoredExperiencesWithDiagnosticData" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\PolicyManager\current\device\System" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\PolicyManager\current\device\System" /V "AllowExperimentation" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /V "value" /T "REG_SZ" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" /V "value" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" /V "value" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Siuf\Rules" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /V "NumberOfSIUFInPeriod" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Speech_OneCore\Preferences" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /V "ModelDownloadAllowed" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /V "HasAccepted" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /V "HasAccepted" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications" /V "DisableNotifications" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows Defender\Features" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows Defender\Features" /V "TamperProtection" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" /V "Auto" /T "REG_SZ" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /V "NetworkThrottlingIndex" /T "REG_DWORD" /D "4294967295" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /V "SystemResponsiveness" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0600DD45-FAF2-4131-A006-0B17509B9F78}" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0671EB05-7D95-4153-A32B-1426B9FE61DB}" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{4738DE7A-BCC1-4E2D-B1B0-CADB044BFA81}" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{6FAC31FA-4A85-4E64-BFD5-2154FF4594B3}" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{87BF85F4-2CE1-4160-96EA-52F554AA28A2}" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{8A9C643C-3D74-4099-B6BD-9C6D170898B1}" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{E3176A65-4E44-4ED3-AA73-3283660ACB9C}" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{FC931F16-B50A-472E-B061-B6F79A71EF59}" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /V "SensorPermissionState" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /V "RPSessionInterval" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" /V "ActivationType" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /V "DiagnosticErrorText" /T "REG_SZ" /D "" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /V "DiagnosticLinkText" /T "REG_SZ" /D "" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /V "DiagnosticErrorText" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKCU\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKCU\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /V "Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /V "Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /V "EnableWebContentEvaluation" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /V "GlobalUserDisabled" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "ContentDeliveryAllowed" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "ContentDeliveryAllowed" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "FeatureManagementEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "FeaturemanagementEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "NumberOfSIUFInPeriod" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "OemPreInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "OemPreInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEverEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "PreInstalledAppsEverEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SilentInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SilentInstalledAppsEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SoftLandingEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SoftLandingEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-310093Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-310093Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338387Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338388Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338388Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338389Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338389Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338393Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338393Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353694Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353694Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353696Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353696Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353698Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContentEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContentEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SystemPaneSuggestionsEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SystemPaneSuggestionsEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /V "DODownloadMode" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /V "DODownloadMode" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{21157C1F-2651-4CC1-90CA-1F28B02263F6}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{235B668D-B2AC-4864-B49C-ED1084F6C9D3}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9D9E0118-1807-4F2E-96E4-2CE57142E196}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{B19F89AF-E3EB-444B-8DEA-202575A71599}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E390DF20-07DF-446D-B962-F5C953072741}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E6AD100E-5F4E-44CD-BE0F-2265D88D14F5}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E83AF229-8640-4D18-A213-E22675EBB2C3}" /V "Value" /T "REG_SZ" /D "Deny" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /V "SearchOrderConfig" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /V "HubMode" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /V "ShowCloudFilesInQuickAccess" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /V "ShowFrequent" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /V "ShowRecent" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /V "SmartScreenEnabled" /T "REG_SZ" /D "Off" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "Hidden" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "HideFileExt" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "LaunchTo" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "Start_TrackProgs" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "TaskbarMn" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "TaskbarMn" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /V "PeopleBand" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /V "ShowHibernateOption" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /V "EnthusiastMode" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /V "SecurityHealth" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /V "Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /V "AllowTelemetry" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /V "MaxTelemetryAllowed" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V "SettingsPageVisibility" /T "REG_SZ" /D "hide:home" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /V "TailoredExperiencesWithDiagnosticDataEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /V "MiscPolicyInfo" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /V "PassedPolicy" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /V "ShippedWithReserves" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "SecurityHealth" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "BingSearchEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "CanCortanaBeEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "CortanaEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "DeviceHistoryEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "HistoryViewEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /V "SyncPolicy" /T "REG_DWORD" /D "5" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /V "Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /V "Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /V "Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /V "Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme" /V "Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /V "Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\PackageState" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\PackageState" /V "Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /V "Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /V "Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /V "Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\DevHomeUpdate" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\DevHomeUpdate" /V "workCompleted" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\OutlookUpdate" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\OutlookUpdate" /V "workCompleted" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\ScheduledDiagnostics" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\ScheduledDiagnostics" /V "EnabledExecution" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\Windows Error Reporting" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /V "Disabled" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\Windows Error Reporting" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /V "DontSendAdditionalData" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\Windows Error Reporting" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /V "DontShowUI" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\Windows Error Reporting" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /V "LoggingDisabled" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Consent" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Consent" /V "DefaultConsent" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Consent" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Consent" /V "DefaultOverrideBehavior" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Edge" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "AlternateErrorPagesEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Edge" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "ConfigureDoNotTrack" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Edge" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "CryptoWalletEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Edge" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "DiagnosticData" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Edge" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "EdgeAssetDeliveryServiceEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Edge" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "EdgeCollectionsEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Edge" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "EdgeShoppingAssistantEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Edge" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "HideFirstRunExperience" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Edge" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "MicrosoftEdgeInsiderPromotionEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Edge" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "PersonalizationReportingEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Edge" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "ShowMicrosoftRewards" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Edge" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "ShowRecommendationsEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Edge" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "UserFeedbackAllowed" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Edge" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "WalletDonationEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Edge" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V "WebWidgetAllowed" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\EdgeUpdate" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\EdgeUpdate" /V "CreateDesktopShortcutDefault" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization" /V "AllowInputPersonalization" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization" /V "RestrictImplicitInkCollection" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization" /V "RestrictImplicitInkCollection" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /V "AllowInputPersonalization" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Messenger\Client" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Messenger\Client" /V "CEIP" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\PushToInstall" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\PushToInstall" /V "DisablePushToInstall" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\PushToInstall" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\PushToInstall" /V "DisablePushToInstall" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\SQMClient" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\SQMClient" /V "CorporateSQMURL" /T "REG_SZ" /D "0.0.0.0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\SQMClient\Windows" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /V "CEIPEnable" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Speech" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Speech" /V "AllowSpeechModelUpdate" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\WMDRM" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\WMDRM" /V "DisableOnline" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /V "DisableEnhancedNotifications" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows Defender" /V "VerifiedAndReputablePolicyState" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /V "NoGenTicket" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /V "DisabledByGroupPolicy" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\AppCompat" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /V "DisableInventory" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\AppCompat" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /V "DisablePCA" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\AppCompat" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /V "DisableUAR" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V "DisableCloudOptimizedContent" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V "DisableConsumerAccountStateContent" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V "DisableTailoredExperiencesWithDiagnosticData" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V "DisableWindowsConsumerFeatures" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\DataCollection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /V "AllowTelemetry" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\DataCollection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /V "DoNotShowFeedbackNotifications" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\DataCollection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /V "DoNotShowFeedbackNotifications" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /V "DODownloadMode" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /V "DisableSearchBoxSuggestions" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /V "ShowRunAsDifferentUserInStart" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\GameDVR" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /V "AllowGameDVR" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /V "PreventHandwritingErrorReports" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /V "PreventHandwritingErrorReports" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /V "DisableLocation" /D "1" /T "REG_DWORD" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /V "DisableLocationScripting" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /V "DisableWindowsLocationProvider" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\OneDrive" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /V "DisableFileSync" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\OneDrive" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /V "DisableFileSyncNGSC" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\OneDrive" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /V "DisableLibrariesDefaultSaveToOneDrive" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\OneDrive" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /V "DisableMeteredNetworkFileSync" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Personalization" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Personalization" /V "NoLockScreenCamera" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /V "DisableQueryremoteServer" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /V "EnableQueryremoteServer" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableAppSyncSettingSync" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableAppSyncSettingSyncUserOverride" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableApplicationSettingSync" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableApplicationSettingSyncUserOverride" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableCredentialsSettingSync" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableCredentialsSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableDesktopThemeSettingSync" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableDesktopThemeSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisablePersonalizationSettingSync" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisablePersonalizationSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableSettingSync" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableSettingSyncUserOverride" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableStartLayoutSettingSync" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableStartLayoutSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableSyncOnPaidNetwork" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableWebBrowserSettingSync" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableWebBrowserSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableWindowsSettingSync" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /V "DisableWindowsSettingSyncUserOverride" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\System" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\System" /V "EnableActivityFeed" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\System" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\System" /V "PublishUserActivities" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\System" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\System" /V "UploadUserActivities" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\TabletPC" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /V "PreventHandwritingDataSharing" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\TabletPC" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /V "PreventHandwritingDataSharing" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" /V "ChatIcon" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /V "Disabled" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowCloudSearch" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowCortana" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowCortanaAboveLock" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "AllowSearchToUseLocation" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchPrivacy" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchUseWeb" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchUseWebOverMeteredConnections" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "DisableWebSearch" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "DisableremovableDriveIndexing" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "PreventUsingAdvancedIndexingOptions" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows" /V "ChatIcon" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /V "DisableAIDataAnalysis" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" /V "TurnOffWindowsCopilot" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\osm" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\osm" /V "enablefileobfuscation" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\osm" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\osm" /V "enablelogging" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\osm" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\osm" /V "enableupload" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common" /V "qmenable" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common" /V "sendcustomerdata" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common" /V "updatereliabilitydata" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" /V "enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" /V "includescreenshot" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\internet" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\internet" /V "useonlinecontent" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\ptwatson" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\ptwatson" /V "ptwoptin" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" /V "blockcontentexecutionfrominternet" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm" /V "enablefileobfuscation" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm" /V "enablelogging" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm" /V "enableupload" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "accesssolution" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "olksolution" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "onenotesolution" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "pptsolution" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "projectsolution" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "publishersolution" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "visiosolution" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "wdsolution" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /V "xlsolution" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "agave" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "appaddins" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "comaddins" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "documentfiles" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /V "templatefiles" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /V "level" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" /V "blockcontentexecutionfrominternet" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security" /V "blockcontentexecutionfrominternet" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Delete "HKCU\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Control\BitLocker" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Control\BitLocker" /V "PreventDeviceEncryption" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Control\CrashControl" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Control\CrashControl" /V "CrashDumpEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Control\FileSystem" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Control\FileSystem" /V "LongPathsEnabled" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Control\FileSystem" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Control\FileSystem" /V "NtfsDisableLastAccessUpdate" /T "REG_DWORD" /D "80000001" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Control\Session Manager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Control\Session Manager" /V "DisableWpbtExecution" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /V "ClearPageFileAtShutdown" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Control\Session Manager\Power" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /V "HiberbootEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Control\remote Assistance" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Control\remote Assistance" /V "fAllowToGetHelp" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\AJRouter" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\AJRouter" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\AJRouter_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\AJRouter_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\ALG" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\ALG" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\ALGـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\ALGـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\AarSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\AarSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\AarSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\AarSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\AppIDSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\AppIDSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\AppIDSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\AppIDSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\AppMgmt" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\AppMgmt" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\AppMgmtـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\AppMgmtـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\AppReadiness" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\AppReadiness" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\AppReadinessـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\AppReadinessـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\AppVClient" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\AppVClient" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\AppVClient_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\AppVClient_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\AppXSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\AppXSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\AppXSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\AppXSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\Appinfo" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\Appinfo" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\Appinfoـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\Appinfoـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\ApxSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\ApxSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\ApxSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\ApxSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\AssignedAccessManagerSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\AssignedAccessManagerSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\AssignedAccessManagerSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\AssignedAccessManagerSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\AxInstSV" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\AxInstSV" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\AxInstSVـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\AxInstSVـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\BDESVC" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\BDESVC" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\BDESVCـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\BDESVCـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\BITS" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\BITS" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\BITSـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\BITSـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\BTAGService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\BTAGService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\BTAGServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\BTAGServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\BcastDVRUserService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\BcastDVRUserService" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\BcastDVRUserService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\BcastDVRUserService_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\BluetoothUserService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\BluetoothUserService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\BluetoothUserServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\BluetoothUserServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\Browser" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\Browser" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\Browserـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\Browserـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\BthAvctpSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\BthAvctpSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\BthAvctpSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\BthAvctpSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\CDPSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\CDPSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\CDPSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\CDPSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\CDPUserSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\CDPUserSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\CDPUserSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\CDPUserSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\COMSysApp" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\COMSysApp" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\COMSysAppـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\COMSysAppـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\CaptureService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\CaptureService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\CaptureServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\CaptureServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\CertPropSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\CertPropSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\CertPropSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\CertPropSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\ClipSVC" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\ClipSVC" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\ClipSVCـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\ClipSVCـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\CloudBackupRestoreSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\CloudBackupRestoreSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\CloudBackupRestoreSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\CloudBackupRestoreSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\CscService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\CscService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\CscServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\CscServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\DPS" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\DPS" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\DPSـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\DPSـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\DcpSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\DcpSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\DcpSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\DcpSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\DevQueryBroker" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\DevQueryBroker" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\DevQueryBrokerـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\DevQueryBrokerـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\DeviceAssociationService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\DeviceAssociationService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\DeviceAssociationServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\DeviceAssociationServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\DeviceInstall" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\DeviceInstall" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\DeviceInstallـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\DeviceInstallـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\DiagTrack" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\DiagTrack" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\DiagTrackـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\DiagTrackـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\DialogBlockingService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\DialogBlockingService" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\DialogBlockingService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\DialogBlockingService_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\DisplayEnhancementService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\DisplayEnhancementService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\DisplayEnhancementServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\DisplayEnhancementServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\DmEnrollmentSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\DmEnrollmentSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\DmEnrollmentSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\DmEnrollmentSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\DoSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\DoSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\DoSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\DoSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\DsSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\DsSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\DsSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\DsSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\DsmSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\DsmSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\DsmSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\DsmSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\DusmSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\DusmSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\DusmSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\DusmSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\EFS" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\EFS" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\EFSـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\EFSـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\EapHost" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\EapHost" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\EapHostـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\EapHostـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\EntAppSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\EntAppSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\EntAppSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\EntAppSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\FDResPub" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\FDResPub" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\FDResPubـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\FDResPubـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\Fax" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\Fax" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\Fax_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\Fax_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\FontCache" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\FontCache" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\FontCacheـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\FontCacheـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\FrameServer" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\FrameServer" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\FrameServerMonitor" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\FrameServerMonitor" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\FrameServerMonitorـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\FrameServerMonitorـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\FrameServerـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\FrameServerـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\GameInputSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\GameInputSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\GameInputSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\GameInputSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\HomeGroupListener" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\HomeGroupListener" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\HomeGroupListenerـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\HomeGroupListenerـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\HomeGroupProvider" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\HomeGroupProvider" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\HomeGroupProviderـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\HomeGroupProviderـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\HvHost" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\HvHost" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\HvHostـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\HvHostـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\IEEtwCollectorService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\IEEtwCollectorService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\IEEtwCollectorServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\IEEtwCollectorServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\InstallService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\InstallService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\InstallServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\InstallServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\InventorySvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\InventorySvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\InventorySvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\InventorySvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\IpxlatCfgSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\IpxlatCfgSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\IpxlatCfgSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\IpxlatCfgSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\KeyIso" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\KeyIso" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\KeyIsoـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\KeyIsoـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\KtmRm" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\KtmRm" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\KtmRmـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\KtmRmـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /V "IRPStackSize" /T "REG_DWORD" /D "00000030" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\LicenseManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\LicenseManager" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\LicenseManagerـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\LicenseManagerـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\LocalKdc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\LocalKdc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\LocalKdcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\LocalKdcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\LxpSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\LxpSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\LxpSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\LxpSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\MDCoreSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\MDCoreSvc" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\MDCoreSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\MDCoreSvc_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\MSDTC" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\MSDTC" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\MSDTCـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\MSDTCـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\MSiSCSI" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\MSiSCSI" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\MSiSCSIـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\MSiSCSIـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\MapsBroker" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\MapsBroker" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\MapsBrokerـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\MapsBrokerـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\McmSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\McmSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\McmSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\McmSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\McpManagementService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\McpManagementService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\McpManagementServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\McpManagementServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\MessagingService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\MessagingService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\MessagingServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\MessagingServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\MixedRealityOpenXRSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\MixedRealityOpenXRSvc" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\MixedRealityOpenXRSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\MixedRealityOpenXRSvc_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\MsKeyboardFilter" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\MsKeyboardFilter" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\MsKeyboardFilter_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\MsKeyboardFilter_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\NPSMSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\NPSMSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\NPSMSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\NPSMSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\NaturalAuthentication" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\NaturalAuthentication" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\NaturalAuthenticationـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\NaturalAuthenticationـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\NcaSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\NcaSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\NcaSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\NcaSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\NcbService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\NcbService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\NcbServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\NcbServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\NcdAutoSetup" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\NcdAutoSetup" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\NcdAutoSetupـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\NcdAutoSetupـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\NetSetupSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\NetSetupSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\NetSetupSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\NetSetupSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\Netlogon" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\Netlogon" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\Netlogonـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\Netlogonـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\Netman" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\Netman" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\Netmanـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\Netmanـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\NgcCtnrSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\NgcCtnrSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\NgcCtnrSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\NgcCtnrSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\NgcSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\NgcSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\NgcSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\NgcSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\NlaSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\NlaSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\NlaSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\NlaSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\OneSyncSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\OneSyncSvc" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\OneSyncSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\OneSyncSvc_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\P9RdrService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\P9RdrService" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\P9RdrService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\P9RdrService_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\PNRPAutoREG" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\PNRPAutoREG" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\PNRPAutoREGـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\PNRPAutoREGـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\PNRPsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\PNRPsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\PNRPsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\PNRPsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\PcaSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\PcaSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\PcaSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\PcaSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\PeerDistSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\PeerDistSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\PeerDistSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\PeerDistSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\PenService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\PenService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\PenServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\PenServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\PerfHost" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\PerfHost" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\PerfHostـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\PerfHostـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\PhoneSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\PhoneSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\PhoneSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\PhoneSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\PlugPlay" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\PlugPlay" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\PlugPlayـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\PlugPlayـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\PolicyAgent" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\PolicyAgent" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\PolicyAgentـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\PolicyAgentـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\PrintDeviceConfigurationService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\PrintDeviceConfigurationService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\PrintDeviceConfigurationServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\PrintDeviceConfigurationServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\PrintNotify" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\PrintNotify" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\PrintNotifyـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\PrintNotifyـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\PrintScanBrokerService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\PrintScanBrokerService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\PrintScanBrokerServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\PrintScanBrokerServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\PushToInstall" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\PushToInstall" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\PushToInstallـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\PushToInstallـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\QWAVE" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\QWAVE" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\QWAVEـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\QWAVEـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\RasAuto" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\RasAuto" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\RasAutoـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\RasAutoـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\RasMan" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\RasMan" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\RasManـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\RasManـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\RemoteAccess" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\RemoteAccess" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\RemoteAccess_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\RemoteAccess_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\RemoteRegistry" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\RemoteRegistry" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\RemoteRegistry_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\RemoteRegistry_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\RetailDemo" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\RetailDemo" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\RetailDemoـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\RetailDemoـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\RmSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\RmSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\RmSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\RmSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\RpcLocator" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\RpcLocator" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\RpcLocatorـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\RpcLocatorـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SCPolicySvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SCPolicySvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SCPolicySvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SCPolicySvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SCardSvr" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SCardSvr" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SCardSvrـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SCardSvrـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SDRSVC" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SDRSVC" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SDRSVCـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SDRSVCـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SEMgrSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SEMgrSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SEMgrSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SEMgrSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SNMPTRAP" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SNMPTRAP" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SNMPTRAPـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SNMPTRAPـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SSDPSRV" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SSDPSRV" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SSDPSRVـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SSDPSRVـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\ScDeviceEnum" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\ScDeviceEnum" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\ScDeviceEnumـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\ScDeviceEnumـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SecurityHealthService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SecurityHealthService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SecurityHealthService_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\Sense" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\Sense" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\Sense_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\Sense_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SensorDataService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SensorDataService" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SensorDataService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SensorDataService_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SensorService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SensorService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SensorServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SensorServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SensrSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SensrSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SensrSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SensrSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SessionEnv" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SessionEnv" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SessionEnvـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SessionEnvـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SharedAccess" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SharedAccess" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SharedAccessـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SharedAccessـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SharedRealitySvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SharedRealitySvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SharedRealitySvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SharedRealitySvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\ShellHWDetection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\ShellHWDetection" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\ShellHWDetectionـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\ShellHWDetectionـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SmsRouter" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SmsRouter" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SmsRouterـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SmsRouterـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\Spooler" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\Spooler" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\Spoolerـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\Spoolerـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SstpSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SstpSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SstpSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SstpSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\StiSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\StiSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\StiSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\StiSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\StorSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\StorSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\StorSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\StorSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SysMain" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SysMain" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\SysMain_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\SysMain_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\TabletInputService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\TabletInputService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\TabletInputServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\TabletInputServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\TapiSrv" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\TapiSrv" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\TapiSrvـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\TapiSrvـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\TermService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\TermService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\TermServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\TermServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\Themes" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\Themes" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\Themesـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\Themesـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\TieringEngineService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\TieringEngineService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\TieringEngineServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\TieringEngineServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\TimeBroker" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\TimeBroker" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\TimeBrokerSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\TimeBrokerSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\TimeBrokerـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\TimeBrokerـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\TokenBroker" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\TokenBroker" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\TokenBrokerـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\TokenBrokerـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\TroubleshootingSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\TroubleshootingSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\TroubleshootingSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\TroubleshootingSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\UI0Detect" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\UI0Detect" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\UI0Detectـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\UI0Detectـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\UdkUserSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\UdkUserSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\UdkUserSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\UdkUserSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\UevAgentService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\UevAgentService" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\UevAgentService_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\UevAgentService_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\UmRdpService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\UmRdpService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\UmRdpServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\UmRdpServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\UnistoreSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\UnistoreSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\UnistoreSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\UnistoreSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\UserDataSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\UserDataSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\UserDataSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\UserDataSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\UsoSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\UsoSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\UsoSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\UsoSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\VSS" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\VSS" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\VSSـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\VSSـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\VacSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\VacSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\VacSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\VacSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\VaultSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\VaultSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\VaultSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\VaultSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\W32Time" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\W32Time" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\W32Timeـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\W32Timeـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WEPHOSTSVC" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WEPHOSTSVC" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WEPHOSTSVCـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WEPHOSTSVCـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WFDSConMgrSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WFDSConMgrSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WFDSConMgrSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WFDSConMgrSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WManSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WManSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WManSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WManSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WPDBusEnum" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WPDBusEnum" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WPDBusEnumـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WPDBusEnumـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WSService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WSService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WSServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WSServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WaaSMedicSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WaaSMedicSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WalletService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WalletService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WalletServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WalletServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WarpJITSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WarpJITSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WarpJITSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WarpJITSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WbioSrvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WbioSrvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WbioSrvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WbioSrvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WcsPlugInService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WcsPlugInService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WcsPlugInServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WcsPlugInServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WdNisSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WdNisSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WdNisSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WdNisSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WdiServiceHost" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WdiServiceHost" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WdiServiceHostـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WdiServiceHostـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WdiSystemHost" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WdiSystemHost" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WdiSystemHostـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WdiSystemHostـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WebClient" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WebClient" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WebClientـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WebClientـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\Wecsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\Wecsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\Wecsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\Wecsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WerSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WerSvc" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WerSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WerSvc_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WiaRpc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WiaRpcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WinDefend" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WinDefend" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WinDefend_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WinDefend_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WinRM" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WinRM" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WinRMـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WinRMـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WlanSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WlanSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WlanSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WlanSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WpcMonSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WpcMonSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WpcMonSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WpcMonSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WpnService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WpnService" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WpnServiceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WpnServiceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WwanSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WwanSvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\WwanSvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\WwanSvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\XblAuthManager" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\XblAuthManager" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\XblAuthManager_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\XblAuthManager_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\XblGameSave" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\XblGameSave" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\XblGameSave_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\XblGameSave_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\XboxGipSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\XboxGipSvc" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\XboxGipSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\XboxGipSvc_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\ZTHELPER" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\ZTHELPER" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\ZTHELPERـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\ZTHELPERـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\autotimesvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\autotimesvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\autotimesvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\autotimesvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\bthserv" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\bthserv" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\bthservـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\bthservـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\camsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\camsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\camsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\camsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\cbdhsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\cbdhsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\cbdhsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\cbdhsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\cloudidsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\cloudidsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\cloudidsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\cloudidsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\dcsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\dcsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\dcsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\dcsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\defragsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\defragsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\defragsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\defragsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.serviceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.serviceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\diagsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\diagsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\diagsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\diagsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\dmwappushservice" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\dmwappushservice" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\dmwappushserviceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\dmwappushserviceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\dot3svc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\dot3svc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\dot3svcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\dot3svcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\edgeupdate" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\edgeupdate" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\edgeupdatem" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\edgeupdatem" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\edgeupdatemـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\edgeupdatemـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\edgeupdateـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\edgeupdateـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\embeddedmode" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\embeddedmode" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\embeddedmodeـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\embeddedmodeـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\fdPHost" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\fdPHost" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\fdPHostـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\fdPHostـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\fhsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\fhsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\fhsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\fhsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\hidserv" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\hidserv" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\hidservـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\hidservـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\hpatchmon" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\hpatchmon" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\hpatchmonـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\hpatchmonـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\icssvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\icssvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\icssvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\icssvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\lfsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\lfsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /V "Status" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\lfsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\lfsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\lltdsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\lltdsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\lltdsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\lltdsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\lmhosts" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\lmhosts" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\lmhostsـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\lmhostsـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\mpssvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\mpssvc" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\mpssvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\mpssvc_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\msiserver" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\msiserver" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\msiserverـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\msiserverـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\netprofm" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\netprofm" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\netprofmـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\netprofmـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\p2pimsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\p2pimsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\p2pimsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\p2pimsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\p2psvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\p2psvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\p2psvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\p2psvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\perceptionsimulation" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\perceptionsimulation" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\perceptionsimulationـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\perceptionsimulationـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\pla" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\pla" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\plaـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\plaـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\refsdedupsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\refsdedupsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\refsdedupsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\refsdedupsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\seclogon" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\seclogon" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\seclogonـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\seclogonـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\shpamsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\shpamsvc" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\shpamsvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\shpamsvc_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\smphost" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\smphost" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\smphostـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\smphostـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\spectrum" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\spectrum" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\spectrumـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\spectrumـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\ssh-agent" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\ssh-agent" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\ssh-agent_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\ssh-agent_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\svsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\svsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\svsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\svsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\swprv" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\swprv" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\swprvـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\swprvـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\tzautoupdate" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\tzautoupdate" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\tzautoupdate_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\tzautoupdate_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\uhssvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\uhssvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\uhssvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\uhssvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\upnphost" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\upnphost" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\upnphostـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\upnphostـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\vds" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\vds" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\vdsـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\vdsـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\vm3dservice" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\vm3dservice" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\vm3dserviceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\vm3dserviceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\vmicguestinterface" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\vmicguestinterface" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\vmicguestinterfaceـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\vmicguestinterfaceـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\vmicheartbeat" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\vmicheartbeat" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\vmicheartbeatـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\vmicheartbeatـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\vmickvpexchange" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\vmickvpexchange" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\vmickvpexchangeـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\vmickvpexchangeـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\vmicrdv" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\vmicrdv" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\vmicrdvـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\vmicrdvـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\vmicshutdown" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\vmicshutdown" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\vmicshutdownـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\vmicshutdownـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\vmictimesync" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\vmictimesync" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\vmictimesyncـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\vmictimesyncـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\vmicvmsession" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\vmicvmsession" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\vmicvmsessionـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\vmicvmsessionـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\vmicvss" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\vmicvss" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\vmicvssـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\vmicvssـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\vmvss" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\vmvss" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\vmvssـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\vmvssـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\wbengine" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\wbengine" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\wbengineـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\wbengineـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\wcncsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\wcncsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\wcncsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\wcncsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\webthreatdefsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\webthreatdefsvc" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\webthreatdefsvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\webthreatdefsvc_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\webthreatdefusersvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\webthreatdefusersvc" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\webthreatdefusersvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\webthreatdefusersvc_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\wercplsupport" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\wercplsupport" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\wercplsupportـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\wercplsupportـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\whesvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\whesvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\whesvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\whesvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\wisvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\wisvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\wisvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\wisvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\wlidsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\wlidsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\wlidsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\wlidsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\wlpasvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\wlpasvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\wlpasvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\wlpasvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\wmiApSrv" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\wmiApSrv" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\wmiApSrvـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\wmiApSrvـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\workfolderssvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\workfolderssvc" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\workfolderssvc_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\workfolderssvc_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\wscsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\wscsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\wscsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\wscsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\wsearch" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\wsearch" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\wsearch_*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\wsearch_*" /V "start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\wuauserv" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\wuauserv" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\wuauservـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\wuauservـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\wudfsvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\wudfsvc" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\Services\wudfsvcـ*" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\Services\wudfsvcـ*" /V "start" /T "REG_DWORD" /D "3" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\CurrentControlSet\services\TermServicentVersion\Search" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\CurrentControlSet\services\TermServicentVersion\Search" /V "AllowCortana" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\SYSTEM\Maps" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\SYSTEM\Maps" /V "AutoUpdateEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /V "Value" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /V "Value" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /V "GlobalUserDisabled" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V "HideSCAMeetNow" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /V "ScoobeSystemSettingEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\Software\Policies\Microsoft\Windows Defender" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Policies\Microsoft\Windows Defender" /V "AllowFastServiceStartup" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\Software\Policies\Microsoft\Windows Defender" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Policies\Microsoft\Windows Defender" /V "DisableAntiSpyware" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\Software\Policies\Microsoft\Windows Defender" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Policies\Microsoft\Windows Defender" /V "DisableAntiVirus" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\Software\Policies\Microsoft\Windows Defender" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Policies\Microsoft\Windows Defender" /V "DisableSpecialRunningModes" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\Software\Policies\Microsoft\Windows Defender" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Policies\Microsoft\Windows Defender" /V "ServiceKeepAlive" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\Software\Policies\Microsoft\Windows Defender\MpEngine" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\MpEngine" /V "MpEnablePus" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableBehaviorMonitoring" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableIOAVProtection" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableOnAccessProtection" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableRealtimeMonitoring" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableRoutinelyTakingAction" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /V "DisableScanOnRealtimeEnable" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\Software\Policies\Microsoft\Windows Defender\Reporting" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\Reporting" /V "DisableEnhancedNotifications" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\Software\Policies\Microsoft\Windows Defender\SpyNet" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\SpyNet" /V "DisableBlockAtFirstSeen" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\Software\Policies\Microsoft\Windows Defender\SpyNet" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\SpyNet" /V "SpynetReporting" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\Software\Policies\Microsoft\Windows Defender\SpyNet" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Policies\Microsoft\Windows Defender\SpyNet" /V "SubmitSamplesConsent" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot" /V "TurnOffWindowsCopilot" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\System\CurrentControlSet\Control\CI\Policy" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\CurrentControlSet\Control\CI\Policy" /V "DisableAntiSpyware" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\System\CurrentControlSet\Control\CI\Policy" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\CurrentControlSet\Control\CI\Policy" /V "DisableAntiVirus" /T "REG_DWORD" /D "1" /F) >nul 2>&1
REG Query "HKCU\System\CurrentControlSet\Control\CI\Policy" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\CurrentControlSet\Control\CI\Policy" /V "PUAProtection" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\System\CurrentControlSet\Control\Session Manager\Power" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\CurrentControlSet\Control\Session Manager\Power" /V "HibernateEnabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /V "Start" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /V "Start" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\System\CurrentControlSet\Services\MDCoreSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\CurrentControlSet\Services\MDCoreSvc" /V "Start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\System\CurrentControlSet\Services\SecurityHealthService" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\CurrentControlSet\Services\SecurityHealthService" /V "Start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\System\CurrentControlSet\Services\SgrmBroker" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\CurrentControlSet\Services\SgrmBroker" /V "Start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\System\CurrentControlSet\Services\WdBoot" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\CurrentControlSet\Services\WdBoot" /V "Start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\System\CurrentControlSet\Services\WdFilter" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\CurrentControlSet\Services\WdFilter" /V "Start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\System\CurrentControlSet\Services\WdNisDrv" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\CurrentControlSet\Services\WdNisDrv" /V "Start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\System\CurrentControlSet\Services\WdNisSvc" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\CurrentControlSet\Services\WdNisSvc" /V "Start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\System\CurrentControlSet\Services\WinDefend" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\CurrentControlSet\Services\WinDefend" /V "Start" /T "REG_DWORD" /D "4" /F) >nul 2>&1
REG Query "HKCU\System\GameConfigStore" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\GameConfigStore" /V "GameDVR_DXGIHonorFSEWindowsCompatible" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\System\GameConfigStore" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\GameConfigStore" /V "GameDVR_EFSEFeatureFlags" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\System\GameConfigStore" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\GameConfigStore" /V "GameDVR_EFSEFeatureFlags" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\System\GameConfigStore" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\GameConfigStore" /V "GameDVR_Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\System\GameConfigStore" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\GameConfigStore" /V "GameDVR_Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\System\GameConfigStore" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\GameConfigStore" /V "GameDVR_Enabled" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\System\GameConfigStore" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\GameConfigStore" /V "GameDVR_FSEBehavior" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\System\GameConfigStore" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\GameConfigStore" /V "GameDVR_FSEBehaviorMode" /T "REG_DWORD" /D "2" /F) >nul 2>&1
REG Query "HKCU\System\GameConfigStore" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\GameConfigStore" /V "GameDVR_HonorUserFSEBehaviorMode" /T "REG_DWORD" /D "0" /F) >nul 2>&1
REG Query "HKCU\System\GameConfigStore" >nul 2>&1 && if %ERRORLEVEL% EQU 0 (REG Add "HKCU\System\GameConfigStore" /V "GameDVR_HonorUserFSEBehaviorMode" /T "REG_DWORD" /D "1" /F) >nul 2>&1

ECHO Done.


ECHO.
ECHO :::::::::::::::::::::::::::::
ECHO ::::: Resetting Network :::::
ECHO :::::::::::::::::::::::::::::
ECHO.

netsh winhttp reset proxy >nul 2>&1
ipconfig /release >nul 2>&1
ipconfig /flushdns >nul 2>&1
ipconfig /renew >nul 2>&1
netsh int ip reset >nul 2>&1
netsh winsock reset >nul 2>&1

ECHO Done.


ECHO.
ECHO ::::::::::::::::::::::::::::::
ECHO ::::: Cleaning Edge Temp :::::
ECHO ::::::::::::::::::::::::::::::
ECHO.

DEL /S /Q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History*" >nul 2>&1
DEL /S /Q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Media History*" >nul 2>&1
DEL /S /Q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Visited Links*" >nul 2>&1
DEL /S /Q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Top Sites*" >nul 2>&1
DEL /S /Q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Network Action Predictor*" >nul 2>&1
DEL /S /Q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Shortcuts*" >nul 2>&1
DEL /S /Q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Network\Cookies*" >nul 2>&1
DEL /S /Q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Web Data*" >nul 2>&1
PushD "%LocalAppData%\Microsoft\Edge\User Data\Default\Session Storage" >nul 2>&1 && (RD /S /Q "%LocalAppData%\Microsoft\Edge\User Data\Default\Session Storage" 2>nul 2>&1 & popd)
PushD "%LocalAppData%\Microsoft\Edge\User Data\Default\Sync Data" >nul 2>&1 && (RD /S /Q "%LocalAppData%\Microsoft\Edge\User Data\Default\Sync Data" 2>nul 2>&1 & popd)
PushD "%LocalAppData%\Microsoft\Edge\User Data\Default\Telemetry" >nul 2>&1 && (RD /S /Q "%LocalAppData%\Microsoft\Edge\User Data\Default\Telemetry" 2>nul 2>&1 & popd)
PushD "%LocalAppData%\Microsoft\Edge\User Data\CrashReports" >nul 2>&1 && (RD /S /Q "%LocalAppData%\Microsoft\Edge\User Data\CrashReports" 2>nul 2>&1 & popd)
PushD "%LocalAppData%\Microsoft\EdgeUpdate\Log" >nul 2>&1 && (RD /S /Q "%LocalAppData%\Microsoft\EdgeUpdate\Log" 2>nul 2>&1 & popd)
PushD "%LocalAppData%\Microsoft\EdgeUpdate\Download" >nul 2>&1 && (RD /S /Q "%LocalAppData%\Microsoft\EdgeUpdate\Download" 2>nul 2>&1 & popd)
PushD "%LocalAppData%\Microsoft\EdgeUpdate\Install" >nul 2>&1 && (RD /S /Q "%LocalAppData%\Microsoft\EdgeUpdate\Install" 2>nul 2>&1 & popd)
PushD "%LocalAppData%\Microsoft\EdgeUpdate\Offline" >nul 2>&1 && (RD /S /Q "%LocalAppData%\Microsoft\EdgeUpdate\Offline" 2>nul 2>&1 & popd)
PushD "%LocalAppData%\Microsoft\Edge\User Data\BrowserMetrics" >nul 2>&1 && (RD /S /Q "%LocalAppData%\Microsoft\Edge\User Data\BrowserMetrics" 2>nul 2>&1 & popd)
PushD "%LocalAppData%\Microsoft\Edge\User Data\Crashpad\reports" >nul 2>&1 && (RD /S /Q "%LocalAppData%\Microsoft\Edge\User Data\Crashpad\reports" 2>nul 2>&1 & popd)
PushD "%LocalAppData%\Microsoft\Edge\User Data\Stability" >nul 2>&1 && (RD /S /Q "%LocalAppData%\Microsoft\Edge\User Data\Stability" 2>nul 2>&1 & popd)
PushD "%LocalAppData%\Microsoft\Edge\User Data\Stability" >nul 2>&1 && (RD /S /Q "%LocalAppData%\Microsoft\Edge\User Data\Stability" 2>nul 2>&1 & popd)
PushD "%LocalAppData%\Microsoft\Edge\User Data\Feature Engagement Tracker" >nul 2>&1 && (RD /S /Q "%LocalAppData%\Microsoft\Edge\User Data\Feature Engagement Tracker" 2>nul 2>&1 & popd)

ECHO Done.


ECHO.
ECHO ::::::::::::::::::::::::::::::::
ECHO ::::: Cleaning Office Temp :::::
ECHO ::::::::::::::::::::::::::::::::
ECHO.

PushD "%LOCALAPPDATA%\Microsoft\Office\16.0\Wef\" >nul 2>&1 && (RD /S /Q "%LOCALAPPDATA%\Microsoft\Office\16.0\Wef\" 2>nul 2>&1 & popd)
PushD "%userprofile%\AppData\Local\Packages\Microsoft.Win32WebViewHost_cw5n1h2txyewy\AC\#!123\INetCache\" >nul 2>&1 && (RD /S /Q "%userprofile%\AppData\Local\Packages\Microsoft.Win32WebViewHost_cw5n1h2txyewy\AC\#!123\INetCache\" 2>nul 2>&1 & popd)
PushD "%userprofile%\AppData\Local\Microsoft\Outlook\HubAppFileCache" >nul 2>&1 && (RD /S /Q "%userprofile%\AppData\Local\Microsoft\Outlook\HubAppFileCache" 2>nul 2>&1 & popd)

ECHO Done.


ECHO.
ECHO :::::::::::::::::::::::::::::::::
ECHO ::::: Cleaning Windows Temp :::::
ECHO :::::::::::::::::::::::::::::::::
ECHO.

RD /S /Q "%LocalAppData%\OO Software" >nul 2>&1
TakeOwn /S %computername% /U %username% /F "%WinDir%\System32\smartscreen.exe" >nul 2>&1
icacls "%WinDir%\System32\smartscreen.exe" /grant:r %username%:f >nul 2>&1
TaskKill /IM /F "smartscreen.exe" >nul 2>&1
DEL "%WinDir%\System32\smartscreen.exe" /S /F /Q >nul 2>&1
TaskKill /F /IM "CrossDeviceResume.exe" >nul 2>&1
CD "%WINDIR%\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy" >nul 2>&1
TakeOwn /F "Microsoft.Web.WebView2.Core.dll" >nul 2>&1
icacls "Microsoft.Web.WebView2.Core.dll" /grant administrators:f >nul 2>&1
DEL /F /Q "%WINDIR%\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\Microsoft.Web.WebView2.Core.dll" >nul 2>&1
CD "%WINDIR%\System32" >nul 2>&1
rundll32.exe pnpclean.dll,RunDLL_PnpClean /drivers /maxclean >nul 2>&1
CMD.exe /C Cleanmgr /sageset:65535 & Cleanmgr /sagerun:65535 >nul 2>&1
cleanmgr /sagerun 1 >nul 2>&1
cleanmgr /verylowdisk >nul 2>&1
RD /S /Q "%SystemDrive%\$GetCurrent" >nul 2>&1
RD /S /Q "%SystemDrive%\$SysReset" >nul 2>&1
RD /S /Q "%SystemDrive%\$Windows.~BT" >nul 2>&1
RD /S /Q "%SystemDrive%\$Windows.~WS" >nul 2>&1
RD /S /Q "%SystemDrive%\$WinREAgent" >nul 2>&1
RD /S /Q "%SystemDrive%\OneDriveTemp" >nul 2>&1
RD /S /Q "%SystemDrive%\Windows.old" >nul 2>&1
PushD "%SystemDrive%\Recovery" >nul 2>&1 && (RD /S /Q "%SystemDrive%\Recovery" 2>nul 2>&1 & popd)
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
PushD "%ProgramData%\USOShared\Logs" >nul 2>&1 && (RD /S /Q "%ProgramData%\USOShared\Logs" 2>nul 2>&1 & popd)
PushD "%LocalAppData%\Microsoft\Windows\WER" >nul 2>&1 && (RD /S /Q "%LocalAppData%\Microsoft\Windows\WER" 2>nul 2>&1 & popd)
PushD "%LocalAppData%\Microsoft\Windows\INetCache" >nul 2>&1 && (RD /S /Q "%LocalAppData%\Microsoft\Windows\INetCache" 2>nul 2>&1 & popd)
PushD "%LocalAppData%\Microsoft\Windows\INetCookies" >nul 2>&1 && (RD /S /Q "%LocalAppData%\Microsoft\Windows\INetCookies" 2>nul 2>&1 & popd)
PushD "%LocalAppData%\Microsoft\Windows\IECompatCache" >nul 2>&1 && (RD /S /Q "%LocalAppData%\Microsoft\Windows\IECompatCache" 2>nul 2>&1 & popd)
PushD "%LocalAppData%\Microsoft\Windows\IECompatUaCache" >nul 2>&1 && (RD /S /Q "%LocalAppData%\Microsoft\Windows\IECompatUaCache" 2>nul 2>&1 & popd)
PushD "%LocalAppData%\Microsoft\Windows\IEDownloadHistory" >nul 2>&1 && (RD /S /Q "%LocalAppData%\Microsoft\Windows\IEDownloadHistory" 2>nul 2>&1 & popd)
PushD "%LocalAppData%\Microsoft\Windows\Temporary Internet Files" >nul 2>&1 && (RD /S /Q "%LocalAppData%\Microsoft\Windows\Temporary Internet Files" 2>nul 2>&1 & popd)
PushD "%LocalAppData%\Microsoft\Windows\WebCache" >nul 2>&1 && (RD /S /Q "%LocalAppData%\Microsoft\Windows\WebCache" 2>nul 2>&1 & popd)
PushD "%WINDIR%\Prefetch" >nul 2>&1 && (RD /S /Q "%WINDIR%\Prefetch" 2>nul 2>&1 & popd)
PushD "%WINDIR%\SoftwareDistribution\Download" >nul 2>&1 && (RD /S /Q "%WINDIR%\SoftwareDistribution\Download" 2>nul 2>&1 & popd)
PushD "%SystemDrive%\$Recycle.Bin" >nul 2>&1 && (RD /S /Q "%SystemDrive%\$Recycle.Bin" 2>nul 2>&1 & popd)
PushD "%WINDIR%\System32\winevt\Logs" >nul 2>&1 && (RD /S /Q "%WINDIR%\System32\winevt\Logs" 2>nul 2>&1 & popd)
PushD "%WINDIR%\Logs" >nul 2>&1 && (RD /S /Q "%WINDIR%\Logs" 2>nul 2>&1 & popd)
PushD "%temp%" >nul 2>&1 && (RD /S /Q "%temp%" 2>nul 2>&1 & popd)
PushD "%SystemDrive%\Temp\" >nul 2>&1 && (RD /S /Q "%SystemDrive%\Temp\" 2>nul 2>&1 & popd)
PushD "%LOCALAPPDATA%\Temp" >nul 2>&1 && (RD /S /Q "%LOCALAPPDATA%\Temp" 2>nul 2>&1 & popd)
PushD "%WINDIR%\Temp" >nul 2>&1 && (RD /S /Q "%WINDIR%\Temp" 2>nul 2>&1 & popd)

ECHO.
ECHO Done.


ECHO.
ECHO :::::::::::::::::::::::::::::
ECHO ::::: Disk Optimization :::::
ECHO :::::::::::::::::::::::::::::
ECHO.

Defrag C: /O

ECHO.
ECHO Done.
ECHO.
ECHO :: Optimization completed successfully. :: Script by S.H.E.I.K.H (GitHub: Sheikh98-DEV)


ECHO.
ECHO :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO :::: Warning. Press any key to shutdown or simply close this batch file. ::::
ECHO :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO.

Pause  >nul 2>&1

RD /S /Q "%SystemDrive%\$GetCurrent" >nul 2>&1
RD /S /Q "%SystemDrive%\$SysReset" >nul 2>&1
RD /S /Q "%SystemDrive%\$Windows.~BT" >nul 2>&1
RD /S /Q "%SystemDrive%\$Windows.~WS" >nul 2>&1
RD /S /Q "%SystemDrive%\$WinREAgent" >nul 2>&1
RD /S /Q "%SystemDrive%\OneDriveTemp" >nul 2>&1
RD /S /Q "%SystemDrive%\Windows.old" >nul 2>&1
PushD "%SystemDrive%\Recovery" >nul 2>&1 && (RD /S /Q "%SystemDrive%\Recovery" 2>nul 2>&1 & popd)
PushD "%ProgramData%\USOShared\Logs" >nul 2>&1 && (RD /S /Q "%ProgramData%\USOShared\Logs" 2>nul 2>&1 & popd)
PushD "%LocalAppData%\Microsoft\Windows\WER" >nul 2>&1 && (RD /S /Q "%LocalAppData%\Microsoft\Windows\WER" 2>nul 2>&1 & popd)
PushD "%LocalAppData%\Microsoft\Windows\INetCache" >nul 2>&1 && (RD /S /Q "%LocalAppData%\Microsoft\Windows\INetCache" 2>nul 2>&1 & popd)
PushD "%LocalAppData%\Microsoft\Windows\INetCookies" >nul 2>&1 && (RD /S /Q "%LocalAppData%\Microsoft\Windows\INetCookies" 2>nul 2>&1 & popd)
PushD "%LocalAppData%\Microsoft\Windows\IECompatCache" >nul 2>&1 && (RD /S /Q "%LocalAppData%\Microsoft\Windows\IECompatCache" 2>nul 2>&1 & popd)
PushD "%LocalAppData%\Microsoft\Windows\IECompatUaCache" >nul 2>&1 && (RD /S /Q "%LocalAppData%\Microsoft\Windows\IECompatUaCache" 2>nul 2>&1 & popd)
PushD "%LocalAppData%\Microsoft\Windows\IEDownloadHistory" >nul 2>&1 && (RD /S /Q "%LocalAppData%\Microsoft\Windows\IEDownloadHistory" 2>nul 2>&1 & popd)
PushD "%LocalAppData%\Microsoft\Windows\Temporary Internet Files" >nul 2>&1 && (RD /S /Q "%LocalAppData%\Microsoft\Windows\Temporary Internet Files" 2>nul 2>&1 & popd)
PushD "%LocalAppData%\Microsoft\Windows\WebCache" >nul 2>&1 && (RD /S /Q "%LocalAppData%\Microsoft\Windows\WebCache" 2>nul 2>&1 & popd)
PushD "%WINDIR%\Prefetch" >nul 2>&1 && (RD /S /Q "%WINDIR%\Prefetch" 2>nul 2>&1 & popd)
PushD "%WINDIR%\SoftwareDistribution\Download" >nul 2>&1 && (RD /S /Q "%WINDIR%\SoftwareDistribution\Download" 2>nul 2>&1 & popd)
PushD "%SystemDrive%\$Recycle.Bin" >nul 2>&1 && (RD /S /Q "%SystemDrive%\$Recycle.Bin" 2>nul 2>&1 & popd)
PushD "%WINDIR%\System32\winevt\Logs" >nul 2>&1 && (RD /S /Q "%WINDIR%\System32\winevt\Logs" 2>nul 2>&1 & popd)
PushD "%WINDIR%\Logs" >nul 2>&1 && (RD /S /Q "%WINDIR%\Logs" 2>nul 2>&1 & popd)
PushD "%temp%" >nul 2>&1 && (RD /S /Q "%temp%" 2>nul 2>&1 & popd)
PushD "%SystemDrive%\Temp\" >nul 2>&1 && (RD /S /Q "%SystemDrive%\Temp\" 2>nul 2>&1 & popd)
PushD "%LOCALAPPDATA%\Temp" >nul 2>&1 && (RD /S /Q "%LOCALAPPDATA%\Temp" 2>nul 2>&1 & popd)
PushD "%WINDIR%\Temp" >nul 2>&1 && (RD /S /Q "%WINDIR%\Temp" 2>nul 2>&1 & popd)
Shutdown /S /T 0
