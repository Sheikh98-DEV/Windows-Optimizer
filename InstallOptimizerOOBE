cd /d "%~dp0"
REG Add "HKLM\Software\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d "0" /f
REG Add "HKLM\System\CurrentControlSet\Services\SgrmBroker" /v "Start" /t REG_DWORD /d "4" /f
REG Add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f
REG Add "HKLM\Software\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d "1" /f
REG Add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableEnhancedNotifications " /t REG_DWORD /d "1" /f
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d "0" /f
REG delete "HKLM\Software\Policies\Microsoft\Windows Defender" /f
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
REG Add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f
REG Add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f
REG delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f
REG delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f
REG delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /f
REG delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /f
REG delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /f
REG Add "HKLM\System\CurrentControlSet\Services\WdBoot" /v "Start" /t REG_DWORD /d "4" /f
REG Add "HKLM\System\CurrentControlSet\Services\MDCoreSvc" /v "Start" /t REG_DWORD /d "4" /f
REG Add "HKLM\System\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d "4" /f
REG Add "HKLM\System\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f
REG Add "HKLM\System\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f
REG Add "HKLM\System\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f
REG Add "HKCU\Software\Microsoft\Edge\SmartScreenEnabled" /ve /t REG_DWORD /d "0" /f
REG Add "HKCU\Software\Microsoft\Edge\SmartScreenPuaEnabled" /ve /t REG_DWORD /d "0" /f
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t "REG_DWORD" /d "0" /f
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "VerifiedAndReputablePolicyState" /t REG_DWORD /d "0" /f
REG Add "HKLM\System\CurrentControlSet\Control\CI\Policy" /v "PUAProtection" /t REG_DWORD /d "0" /f
REG Add "HKLM\System\CurrentControlSet\Control\CI\Policy" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
REG Add "HKLM\System\CurrentControlSet\Control\CI\Policy" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V SettingsPageVisibility /T REG_SZ /D hide:home /F
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d "0" /f
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d "0" /f
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
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d "0" /f
REG Add "HKLM\Software\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d "0" /f
REG Add "HKLM\Software\Policies\Microsoft\PushToInstall" /v "DisablePushToInstall" /t REG_DWORD /d "1" /f
REG Add "HKLM\Software\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f
REG delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /f
REG delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /f
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /v "MiscPolicyInfo" /t REG_DWORD /d "2" /f
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /v "PassedPolicy" /t REG_DWORD /d "0" /f
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /v "ShippedWithReserves" /t REG_DWORD /d "0" /f
REG Add "HKLM\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v "DisableQueryRemoteServer" /t REG_DWORD /d "0" /f
REG Add "HKLM\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v "EnableQueryRemoteServer" /t REG_DWORD /d "0" /f
REG Add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AeDebug" /v "Auto" /t REG_SZ /d "0" /f
REG Add "HKLM\Software\Microsoft\PCHealth\ErrorReporting" /v "DoReport" /t REG_DWORD /d "0" /f
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
REG Add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d "0" /f
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d "1" /f
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d "0" /f
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d "1" /f
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f
REG Add "HKLM\Software\Microsoft\PCHealth\ErrorReporting" /v "ShowUI" /t REG_DWORD /d "0" /f
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d "1" /f
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d "1" /f
REG Add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f
REG Add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d "1" /f
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d "0" /f
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d "0" /f
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowCloudFilesInQuickAccess" /t REG_DWORD /d "0" /f
REG Add "HKCR\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\ShellFolder" /v "Attributes" /t REG_DWORD /d "2962489444" /f
REG Add "HKCU\Software\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f
REG delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f
REG Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "HubMode" /t REG_DWORD /d "1" /f
REG delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /f
REG delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /f
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "1" /f
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f
REG Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v "EnthusiastMode" /t REG_DWORD /d "1" /f
REG Add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /V CrashDumpEnabled /T REG_DWORD /D 0 /F
REG Add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /V NtfsDisableLastAccessUpdate /T REG_DWORD /D 80000001 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V DisableRemovableDriveIndexing /T REG_DWORD /D 1 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V PreventUsingAdvancedIndexingOptions /T REG_DWORD /D 1 /F
REG Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /V RPSessionInterval /T REG_DWORD /D 0 /F
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
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V ShowMicrosoftRewards /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V WebWidgetAllowed /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V DiagnosticData /T REG_DWORD /D 0 /F
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V EdgeAssetDeliveryServiceEnabled /T REG_DWORD /D 0 /F
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
REG Add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /V fAllowToGetHelp /T REG_DWORD /D 0 /F
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
sc config "ALG" start=Demand
sc config "AppIDSvc" start=Demand
sc config "AppMgmt" start=Demand
sc config "AppReadiness" start=Demand
sc config "AppXSvc" start=Demand
sc config "Appinfo" start=Demand
sc config "AxInstSV" start=Demand
sc config "BDESVC" start=Demand
sc config "BTAGService" start=Demand
sc config "BcastDVRUserService_*" start=Demand
sc config "BluetoothUserService_*" start=Demand
sc config "Browser" start=Demand
sc config "CDPSvc" start=Demand
sc config "COMSysApp" start=Demand
sc config "CaptureService_*" start=Demand
sc config "CertPropSvc" start=Demand
sc config "ClipSVC" start=Demand
sc config "ConsentUxUserSvc_*" start=Demand
sc config "CredentialEnrollmentManagerUserSvc_*" start=Demand
sc config "CscService" start=Demand
sc config "DcpSvc" start=Demand
sc config "DevQueryBroker" start=Demand
sc config "DeviceAssociationBrokerSvc_*" start=Demand
sc config "DeviceAssociationService" start=Demand
sc config "DeviceInstall" start=Demand
sc config "DevicePickerUserSvc_*" start=Demand
sc config "DevicesFlowUserSvc_*" start=Demand
sc config "DisplayEnhancementService" start=Demand
sc config "DmEnrollmentSvc" start=Demand
sc config "EFS" start=Demand
sc config "EapHost" start=Demand
sc config "EntAppSvc" start=Demand
sc config "FDResPub" start=Demand
sc config "Fax" start=Demand
sc config "FrameServer" start=Demand
sc config "FrameServerMonitor" start=Demand
sc config "GraphicsPerfSvc" start=Demand
sc config "HomeGroupListener" start=Demand
sc config "HomeGroupProvider" start=Demand
sc config "HvHost" start=Demand
sc config "IEEtwCollectorService" start=Demand
sc config "IKEEXT" start=Demand
sc config "InstallService" start=Demand
sc config "InventorySvc" start=Demand
sc config "IpxlatCfgSvc" start=Demand
sc config "KtmRm" start=Demand
sc config "LicenseManager" start=Demand
sc config "LxpSvc" start=Demand
sc config "MSDTC" start=Demand
sc config "MSiSCSI" start=Demand
sc config "McpManagementService" start=Demand
sc config "MessagingService_*" start=Demand
sc config "MicrosoftEdgeElevationService" start=Demand
sc config "MixedRealityOpenXRSvc" start=Demand
sc config "MsKeyboardFilter" start=Demand
sc config "NPSMSvc_*" start=Demand
sc config "NaturalAuthentication" start=Demand
sc config "NcaSvc" start=Demand
sc config "NcbService" start=Demand
sc config "NcdAutoSetup" start=Demand
sc config "NetSetupSvc" start=Demand
sc config "Netman" start=Demand
sc config "NgcCtnrSvc" start=Demand
sc config "NgcSvc" start=Demand
sc config "NlaSvc" start=Demand
sc config "P9RdrService_*" start=Demand
sc config "PNRPAutoREG" start=Demand
sc config "PNRPsvc" start=Demand
sc config "PcaSvc" start=Demand
sc config "PeerDistSvc" start=Demand
sc config "PenService_*" start=Demand
sc config "PerfHost" start=Demand
sc config "PhoneSvc" start=Demand
sc config "PimIndexMaintenanceSvc_*" start=Demand
sc config "PlugPlay" start=Demand
sc config "PolicyAgent" start=Demand
sc config "PrintNotify" start=Demand
sc config "PrintWorkflowUserSvc_*" start=Demand
sc config "PushToInstall" start=Demand
sc config "QWAVE" start=Demand
sc config "RasAuto" start=Demand
sc config "RasMan" start=Demand
sc config "RetailDemo" start=Demand
sc config "RmSvc" start=Demand
sc config "RpcLocator" start=Demand
sc config "SCPolicySvc" start=Demand
sc config "SCardSvr" start=Demand
sc config "SDRSVC" start=Demand
sc config "SEMgrSvc" start=Demand
sc config "SNMPTRAP" start=Demand
sc config "SNMPTrap" start=Demand
sc config "SSDPSRV" start=Demand
sc config "ScDeviceEnum" start=Demand
sc config "SecurityHealthService" start=Demand
sc config "Sense" start=Demand
sc config "SensorDataService" start=Demand
sc config "SensorService" start=Demand
sc config "SensrSvc" start=Demand
sc config "SessionEnv" start=Demand
sc config "SharedAccess" start=Demand
sc config "SharedRealitySvc" start=Demand
sc config "SmsRouter" start=Demand
sc config "SstpSvc" start=Demand
sc config "StiSvc" start=Demand
sc config "StorSvc" start=Demand
sc config "TabletInputService" start=Demand
sc config "TapiSrv" start=Demand
sc config "TieringEngineService" start=Demand
sc config "TimeBroker" start=Demand
sc config "TimeBrokerSvc" start=Demand
sc config "TokenBroker" start=Demand
sc config "TroubleshootingSvc" start=Demand
sc config "TrustedInstaller" start=Demand
sc config "UI0Detect" start=Demand
sc config "UdkUserSvc_*" start=Demand
sc config "UmRdpService" start=Demand
sc config "UnistoreSvc_*" start=Demand
sc config "UserDataSvc_*" start=Demand
sc config "UsoSvc" start=Demand
sc config "VSS" start=Demand
sc config "VacSvc" start=Demand
sc config "W32Time" start=Demand
sc config "WEPHOSTSVC" start=Demand
sc config "WFDSConMgrSvc" start=Demand
sc config "WMPNetworkSvc" start=Demand
sc config "WManSvc" start=Demand
sc config "WPDBusEnum" start=Demand
sc config "WSService" start=Demand
sc config "WaaSMedicSvc" start=Demand
sc config "WalletService" start=Demand
sc config "WarpJITSvc" start=Demand
sc config "WcsPlugInService" start=Demand
sc config "WdNisSvc" start=Demand
sc config "WdiServiceHost" start=Demand
sc config "WdiSystemHost" start=Demand
sc config "WebClient" start=Demand
sc config "Wecsvc" start=Demand
sc config "WerSvc" start=Demand
sc config "WiaRpc" start=Demand
sc config "WinHttpAutoProxySvc" start=Demand
sc config "WinRM" start=Demand
sc config "WpcMonSvc" start=Demand
sc config "WpnService" start=Demand
sc config "XblAuthManager" start=Demand
sc config "XblGameSave" start=Demand
sc config "XboxGipSvc" start=Demand
sc config "XboxNetApiSvc" start=Demand
sc config "autotimesvc" start=Demand
sc config "bthserv" start=Demand
sc config "camsvc" start=Demand
sc config "cbdhsvc_*" start=Demand
sc config "cloudidsvc" start=Demand
sc config "dcsvc" start=Demand
sc config "defragsvc" start=Demand
sc config "diagnosticshub.standardcollector.service" start=Demand
sc config "diagsvc" start=Demand
sc config "dmwappushservice" start=Demand
sc config "dot3svc" start=Demand
sc config "edgeupdate" start=Demand
sc config "edgeupdatem" start=Demand
sc config "embeddedmode" start=Demand
sc config "fdPHost" start=Demand
sc config "fhsvc" start=Demand
sc config "hidserv" start=Demand
sc config "icssvc" start=Demand
sc config "lfsvc" start=Demand
sc config "lltdsvc" start=Demand
sc config "lmhosts" start=Demand
sc config "msiserver" start=Demand
sc config "netprofm" start=Demand
sc config "p2pimsvc" start=Demand
sc config "p2psvc" start=Demand
sc config "perceptionsimulation" start=Demand
sc config "pla" start=Demand
sc config "seclogon" start=Demand
sc config "smphost" start=Demand
sc config "spectrum" start=Demand
sc config "svsvc" start=Demand
sc config "swprv" start=Demand
sc config "upnphost" start=Demand
sc config "vds" start=Demand
sc config "vm3dservice" start=Demand
sc config "vmicguestinterface" start=Demand
sc config "vmicheartbeat" start=Demand
sc config "vmickvpexchange" start=Demand
sc config "vmicrdv" start=Demand
sc config "vmicshutdown" start=Demand
sc config "vmictimesync" start=Demand
sc config "vmicvmsession" start=Demand
sc config "vmicvss" start=Demand
sc config "vmvss" start=Demand
sc config "wbengine" start=Demand
sc config "wcncsvc" start=Demand
sc config "webthreatdefsvc" start=Demand
sc config "wercplsupport" start=Demand
sc config "wisvc" start=Demand
sc config "wlidsvc" start=Demand
sc config "wlpasvc" start=Demand
sc config "wmiApSrv" start=Demand
sc config "workfolderssvc" start=Demand
sc config "wuauserv" start=Demand
sc config "wudfsvc" start=Demand
sc config "MapsBroker" start=Demand
sc config "GameInputSvc" start=Demand
sc config "TermService" start=Demand
sc config "EventSystem" start=Demand
sc config "DusmSvc" start=Demand
sc config "DoSvc" start=Demand
sc config "DPS" start=Demand
sc config "AarSvc" start=Demand
sc config "AssignedAccessManagerSvc" start=Demand
sc config "BthAvctpSvc" start=Demand
sc config "BluetoothUserService" start=Demand
sc config "CaptureService" start=Demand
sc config "cbdhsvc" start=Demand
sc config "CloudBackupRestoreSvc" start=Demand
sc config "DiagTrack" start=Demand
sc config "ConsentUxUserSvc" start=Demand
sc config "PimIndexMaintenanceSvc" start=Demand
sc config "DsSvc" start=Demand
sc config "DeviceAssociationBrokerSvc" start=Demand
sc config "DevicePickerUserSvc" start=Demand
sc config "TrkWks" start=Demand
sc config "hpatchmon" start=Demand
sc config "wlpasvc\wlpasvc" start=Demand
sc config "MessagingService" start=Demand
sc config "wlidsvc\wlidsvc" start=Demand
sc config "Netlogon" start=Demand
sc config "NPSMSvc" start=Demand
sc config "PenService" start=Demand
sc config "PrintDeviceConfigurationService" start=Demand
sc config "Spooler" start=Demand
sc config "PrintScanBrokerService" start=Demand
sc config "PrintWorkflowUserSvc" start=Demand
sc config "refsdedupsvc" start=Demand
sc config "wscsvc" start=Demand
sc config "OneSyncSvc" start=Demand
sc config "SysMain" start=Demand
sc config "SENS" start=Demand
sc config "UserDataSvc" start=Demand
sc config "UnistoreSvc" start=Demand
sc config "webthreatdefusersvc" start=Demand
sc config "WinDefend" start=Demand
sc config "WbioSrvc" start=Demand
sc config "mpssvc" start=Demand
sc config "WSearch" start=Demand
sc config "WwanSvc" start=Demand
sc config "ZTHELPER" start=Demand
sc stop "webthreatdefsvc"
sc config "webthreatdefsvc" start= disabled
sc stop "webthreatdefusersvc"
sc config "webthreatdefusersvc" start= disabled
sc stop "WerSvc"
sc config "WerSvc" start= disabled
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
sc stop "RemoteAccess"
sc config "RemoteAccess" start=disabled
sc stop "RemoteREGistry"
sc config "RemoteREGistry" start=disabled
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
schtasks /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable
schtasks /Change /TN "Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
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
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Cellular" /Disable
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Logon" /Disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsToastTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsUpdateTask" /Disable
schtasks /Change /TN "Microsoft\Windows\MUI\LPRemove" /Disable
schtasks /Change /TN "Microsoft\Windows\Multimedia\SystemSoundsService" /Disable
schtasks /Change /TN "Microsoft\Windows\NlaSvc\WiFiTask" /Disable
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Disable
schtasks /Change /TN "Microsoft\Windows\Printing\EduPrintProv" /Disable
schtasks /Change /TN "Microsoft\Windows\Printing\PrinterCleanupTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Printing\PrintJobCleanupTask" /Disable
schtasks /Change /TN "Microsoft\Windows\PushToInstall\REGistration" /Disable
schtasks /Change /TN "Microsoft\Windows\Ras\MobilityManager" /Disable
schtasks /Change /TN "Microsoft\Windows\RecoveryEnvironment\VerifyWinRE" /Disable
schtasks /Change /TN "Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" /Disable
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
takeown /s %computername% /u %username% /f "%WinDir%\System32\smartscreen.exe"
icacls "%WinDir%\System32\smartscreen.exe" /grant:r %username%:F
taskkill /im smartscreen.exe /f
del "%WinDir%\System32\smartscreen.exe" /s /f /q
powercfg.exe /hibernate off
powercfg -h off
reagentc /info
reagentc /disable
fsutil storagereserve query C:
fsutil behavior set disablelastaccess 1
fsutil behavior set disabledeletenotify 0
DISM /Online /Disable-Feature /FeatureName:Recall /Quiet /NoRestart
DISM /Online /Set-ReservedStorageState /State:Disabled /Quiet /NoRestart
DISM /online /remove-package /packagename:Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.1742.1.10
DISM /online /cleanup-image /analyzecomponentstore
DISM /online /cleanup-image /startcomponentcleanup
DISM /online /cleanup-image /startcomponentcleanup /resetbase
chkdsk
dism /online /cleanup-image /checkhealth
dism /online /cleanup-image /scanhealth
dism /online /cleanup-image /restorehealth
sfc /scannow
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
pushd "%LocalAppData%\Microsoft\Edge\User Data\Feature Engagement Tracker" && (rd /s /q "%LocalAppData%\Microsoft\Edge\User Data\Feature Engagement Tracker" 2>nul & popd)
pushd "%LOCALAPPDATA%\Microsoft\Office\16.0\Wef\" && (rd /s /q "%LOCALAPPDATA%\Microsoft\Office\16.0\Wef\" 2>nul & popd)
pushd "%userprofile%\AppData\Local\Packages\Microsoft.Win32WebViewHost_cw5n1h2txyewy\AC\#!123\INetCache\" && (rd /s /q "%userprofile%\AppData\Local\Packages\Microsoft.Win32WebViewHost_cw5n1h2txyewy\AC\#!123\INetCache\" 2>nul & popd)
pushd "%userprofile%\AppData\Local\Microsoft\Outlook\HubAppFileCache" && (rd /s /q "%userprofile%\AppData\Local\Microsoft\Outlook\HubAppFileCache" 2>nul & popd)
rundll32.exe pnpclean.dll,RunDLL_PnpClean /drivers /maxclean
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
defrag C: /O
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
