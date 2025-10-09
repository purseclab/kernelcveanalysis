# Android Env

Scripts to analyze things about the environbbment of an android device over adb.

Setup ssh port forwarding for adb on local machine running kexploit:
```sh
ssh -L localhost:5037:localhost:5037 cuttlefish-user@cuttlefish-host
```

## Example Output and Policies

Policies regulating which services untrusted_app is allowed to discover:
```
$ sesearch sepolicy --allow -s untrusted_app -c service_manager -p find
allow untrusted_app apc_service:service_manager find;
allow untrusted_app credstore_service:service_manager find;
allow untrusted_app hal_drm_service:service_manager find;
allow untrusted_app hal_graphics_allocator_service:service_manager find;
allow untrusted_app hal_neuralnetworks_service:service_manager find;
allow untrusted_app keystore_maintenance_service:service_manager find;
allow untrusted_app keystore_service:service_manager find;
allow untrusted_app legacykeystore_service:service_manager find;
allow untrusted_app_all app_api_service:service_manager find;
allow untrusted_app_all audioserver_service:service_manager find;
allow untrusted_app_all cameraserver_service:service_manager find;
allow untrusted_app_all drmserver_service:service_manager find;
allow untrusted_app_all mediadrmserver_service:service_manager find;
allow untrusted_app_all mediaextractor_service:service_manager find;
allow untrusted_app_all mediametrics_service:service_manager find;
allow untrusted_app_all mediaserver_service:service_manager find;
allow untrusted_app_all nfc_service:service_manager find;
allow untrusted_app_all radio_service:service_manager find;
allow untrusted_app_all virtualization_service:service_manager find;
allow untrusted_app_all vr_manager_service:service_manager find;
```

As an example, the first line specifies that a domain with type of `untrusted_app`
can perform the `find` action from the `service_manager` class on an object of type `apc_service`.

`apc_service` is not actually a concrete service name, but an selinux type.
The file `/system/etc/selinux/plat_service_contexts` specifies a mapping between service names and selinux labels (which include the selinux type).
An example output portion of that file is shown below:
```
android.security.apc                      u:object_r:apc_service:s0
android.security.authorization            u:object_r:authorization_service:s0
android.security.compat                   u:object_r:keystore_compat_hal_service:s0
android.security.dice.IDiceMaintenance    u:object_r:dice_maintenance_service:s0
android.security.dice.IDiceNode           u:object_r:dice_node_service:s0
android.security.identity                 u:object_r:credstore_service:s0
android.security.keystore                 u:object_r:keystore_service:s0
android.security.legacykeystore           u:object_r:legacykeystore_service:s0
android.security.maintenance              u:object_r:keystore_maintenance_service:s0
android.security.metrics                  u:object_r:keystore_metrics_service:s0
android.security.remoteprovisioning       u:object_r:remoteprovisioning_service:s0
android.security.remoteprovisioning.IRemotelyProvisionedKeyPool u:object_r:remotelyprovisionedkeypool_service:s0
android.service.gatekeeper.IGateKeeperService    u:object_r:gatekeeper_service:s0
android.system.composd                    u:object_r:compos_service:s0
android.system.virtualizationservice      u:object_r:virtualization_service:s0
ambient_context                           u:object_r:ambient_context_service:s0
app_binding                               u:object_r:app_binding_service:s0
app_hibernation                           u:object_r:app_hibernation_service:s0
app_integrity                             u:object_r:app_integrity_service:s0
app_prediction                            u:object_r:app_prediction_service:s0
app_search                                u:object_r:app_search_service:s0
apexservice                               u:object_r:apex_service:s0
attestation_verification                  u:object_r:attestation_verification_service:s0
blob_store                                u:object_r:blob_store_service:s0
gsiservice                                u:object_r:gsi_service:s0
appops                                    u:object_r:appops_service:s0
appwidget                                 u:object_r:appwidget_service:s0
```

An example output of the tool in its current state for reachable service nemses for `untrusted_app` and `untrusted_app_all` is shown below:
```
tools/read_file: 1 file pushed, 0 skipped. 103.7 MB/s (3305512 bytes in 0.030s)
tools/dump_seccomp_filter: 1 file pushed, 0 skipped. 100.2 MB/s (3311472 bytes in 0.032s)
tools/runas: 1 file pushed, 0 skipped. 102.1 MB/s (3337192 bytes in 0.031s)
untrusted_app can access service:
ServiceInfo(service_name='android.security.apc', service_interface='android.security.apc.IProtectedConfirmation')
ServiceInfo(service_name='android.security.identity', service_interface='android.security.identity.ICredentialStoreFactory')
ServiceInfo(service_name='android.hardware.drm.IDrmFactory/clearkey', service_interface='android.hardware.drm.IDrmFactory')
ServiceInfo(service_name='android.hardware.graphics.allocator.IAllocator/default', service_interface='android.hardware.graphics.allocator.IAllocator')
ServiceInfo(service_name='android.hardware.neuralnetworks.IDevice/nnapi-sample_all', service_interface='android.hardware.neuralnetworks.IDevice')
ServiceInfo(service_name='android.hardware.neuralnetworks.IDevice/nnapi-sample_float_fast', service_interface='android.hardware.neuralnetworks.IDevice')
ServiceInfo(service_name='android.hardware.neuralnetworks.IDevice/nnapi-sample_float_slow', service_interface='android.hardware.neuralnetworks.IDevice')
ServiceInfo(service_name='android.hardware.neuralnetworks.IDevice/nnapi-sample_minimal', service_interface='android.hardware.neuralnetworks.IDevice')
ServiceInfo(service_name='android.hardware.neuralnetworks.IDevice/nnapi-sample_quant', service_interface='android.hardware.neuralnetworks.IDevice')
ServiceInfo(service_name='android.hardware.neuralnetworks.IDevice/nnapi-sample_sl_shim', service_interface='android.hardware.neuralnetworks.IDevice')
ServiceInfo(service_name='android.security.maintenance', service_interface='android.security.maintenance.IKeystoreMaintenance')
ServiceInfo(service_name='android.system.keystore2.IKeystoreService/default', service_interface='android.system.keystore2.IKeystoreService')
ServiceInfo(service_name='android.security.legacykeystore', service_interface='android.security.legacykeystore.ILegacyKeystore')
ServiceInfo(service_name='batterystats', service_interface='com.android.internal.app.IBatteryStats')
ServiceInfo(service_name='statusbar', service_interface='com.android.internal.statusbar.IStatusBarService')
ServiceInfo(service_name='graphicsstats', service_interface='android.view.IGraphicsStats')
ServiceInfo(service_name='legacy_permission', service_interface='android.permission.ILegacyPermissionManager')
ServiceInfo(service_name='display', service_interface='android.hardware.display.IDisplayManager')
ServiceInfo(service_name='memtrack.proxy', service_interface='android.hardware.memtrack.IMemtrack')
ServiceInfo(service_name='virtualdevice', service_interface='android.companion.virtual.IVirtualDeviceManager')
ServiceInfo(service_name='procstats', service_interface='com.android.internal.app.procstats.IProcessStats')
ServiceInfo(service_name='media_router', service_interface='android.media.IMediaRouterService')
ServiceInfo(service_name='account', service_interface='android.accounts.IAccountManager')
ServiceInfo(service_name='textservices', service_interface='com.android.internal.textservice.ITextServicesManager')
ServiceInfo(service_name='sdk_sandbox', service_interface='android.app.sdksandbox.ISdkSandboxManager')
ServiceInfo(service_name='slice', service_interface='android.app.slice.ISliceManager')
ServiceInfo(service_name='package_native', service_interface='android.content.pm.IPackageManagerNative')
ServiceInfo(service_name='sensorservice', service_interface='android.gui.SensorServer')
ServiceInfo(service_name='connectivity_native', service_interface='android.net.connectivity.aidl.ConnectivityNative')
ServiceInfo(service_name='role', service_interface='android.app.role.IRoleManager')
ServiceInfo(service_name='thermalservice', service_interface='android.os.IThermalService')
ServiceInfo(service_name='file_integrity', service_interface='android.security.IFileIntegrityService')
ServiceInfo(service_name='dropbox', service_interface='com.android.internal.os.IDropBoxManagerService')
ServiceInfo(service_name='permission', service_interface='android.os.IPermissionController')
ServiceInfo(service_name='audio', service_interface='android.media.IAudioService')
ServiceInfo(service_name='servicediscovery', service_interface='android.net.nsd.INsdManager')
ServiceInfo(service_name='gpu', service_interface='android.graphicsenv.IGpuService')
ServiceInfo(service_name='telephony.registry', service_interface='com.android.internal.telephony.ITelephonyRegistry')
ServiceInfo(service_name='font', service_interface='com.android.internal.graphics.fonts.IFontManager')
ServiceInfo(service_name='appwidget', service_interface='com.android.internal.appwidget.IAppWidgetService')
ServiceInfo(service_name='sec_key_att_app_id_provider', service_interface='android.security.keymaster.IKeyAttestationApplicationIdProvider')
ServiceInfo(service_name='notification', service_interface='android.app.INotificationManager')
ServiceInfo(service_name='user', service_interface='android.os.IUserManager')
ServiceInfo(service_name='connmetrics', service_interface='android.net.IIpConnectivityMetrics')
ServiceInfo(service_name='incidentcompanion', service_interface='android.os.IIncidentCompanion')
ServiceInfo(service_name='restrictions', service_interface='android.content.IRestrictionsManager')
ServiceInfo(service_name='hardware_properties', service_interface='android.os.IHardwarePropertiesManager')
ServiceInfo(service_name='lights', service_interface='android.hardware.lights.ILightsManager')
ServiceInfo(service_name='android.frameworks.stats.IStats/default', service_interface='android.frameworks.stats.IStats')
ServiceInfo(service_name='storagestats', service_interface='android.app.usage.IStorageStatsManager')
ServiceInfo(service_name='bluetooth_manager', service_interface='android.bluetooth.IBluetoothManager')
ServiceInfo(service_name='reboot_readiness', service_interface='android.scheduling.IRebootReadinessManager')
ServiceInfo(service_name='launcherapps', service_interface='android.content.pm.ILauncherApps')
ServiceInfo(service_name='device_state', service_interface='android.hardware.devicestate.IDeviceStateManager')
ServiceInfo(service_name='accessibility', service_interface='android.view.accessibility.IAccessibilityManager')
ServiceInfo(service_name='clipboard', service_interface='android.content.IClipboard')
ServiceInfo(service_name='jobscheduler', service_interface='android.app.job.IJobScheduler')
ServiceInfo(service_name='media_communication', service_interface='android.media.IMediaCommunicationService')
ServiceInfo(service_name='rollback', service_interface='android.content.rollback.IRollbackManager')
ServiceInfo(service_name='smartspace', service_interface='android.app.smartspace.ISmartspaceManager')
ServiceInfo(service_name='biometric', service_interface='android.hardware.biometrics.IBiometricService')
ServiceInfo(service_name='consumer_ir', service_interface='android.hardware.IConsumerIrService')
ServiceInfo(service_name='auth', service_interface='android.hardware.biometrics.IAuthService')
ServiceInfo(service_name='blob_store', service_interface='android.app.blob.IBlobStoreManager')
ServiceInfo(service_name='media_metrics', service_interface='android.media.metrics.IMediaMetricsManager')
ServiceInfo(service_name='crossprofileapps', service_interface='android.content.pm.ICrossProfileApps')
ServiceInfo(service_name='network_management', service_interface='android.os.INetworkManagementService')
ServiceInfo(service_name='vcn_management', service_interface='android.net.vcn.IVcnManagementService')
ServiceInfo(service_name='wifip2p', service_interface='android.net.wifi.p2p.IWifiP2pManager')
ServiceInfo(service_name='country_detector', service_interface='android.location.ICountryDetector')
ServiceInfo(service_name='usagestats', service_interface='android.app.usage.IUsageStatsManager')
ServiceInfo(service_name='content', service_interface='android.content.IContentService')
ServiceInfo(service_name='app_search', service_interface='android.app.appsearch.aidl.IAppSearchManager')
ServiceInfo(service_name='webviewupdate', service_interface='android.webkit.IWebViewUpdateService')
ServiceInfo(service_name='ethernet', service_interface='android.net.IEthernetManager')
ServiceInfo(service_name='tare', service_interface='android.app.tare.IEconomyManager')
ServiceInfo(service_name='textclassification', service_interface='android.service.textclassifier.ITextClassifierService')
ServiceInfo(service_name='backup', service_interface='android.app.backup.IBackupManager')
ServiceInfo(service_name='soundtrigger', service_interface='com.android.internal.app.ISoundTriggerService')
ServiceInfo(service_name='voiceinteraction', service_interface='com.android.internal.app.IVoiceInteractionManagerService')
ServiceInfo(service_name='ipsec', service_interface='android.net.IIpSecService')
ServiceInfo(service_name='netpolicy', service_interface='android.net.INetworkPolicyManager')
ServiceInfo(service_name='batteryproperties', service_interface='android.os.IBatteryPropertiesRegistrar')
ServiceInfo(service_name='alarm', service_interface='android.app.IAlarmManager')
ServiceInfo(service_name='permission_checker', service_interface='android.permission.IPermissionChecker')
ServiceInfo(service_name='lock_settings', service_interface='com.android.internal.widget.ILockSettings')
ServiceInfo(service_name='wallpaper', service_interface='android.app.IWallpaperManager')
ServiceInfo(service_name='search_ui', service_interface='android.app.search.ISearchUiManager')
ServiceInfo(service_name='location', service_interface='android.location.ILocationManager')
ServiceInfo(service_name='shortcut', service_interface='android.content.pm.IShortcutService')
ServiceInfo(service_name='connectivity', service_interface='android.net.IConnectivityManager')
ServiceInfo(service_name='imms', service_interface='com.android.internal.telephony.IMms')
ServiceInfo(service_name='tethering', service_interface='android.net.ITetheringConnector')
ServiceInfo(service_name='android.service.gatekeeper.IGateKeeperService', service_interface='android.service.gatekeeper.IGateKeeperService')
ServiceInfo(service_name='deviceidle', service_interface='android.os.IDeviceIdleController')
ServiceInfo(service_name='activity_task', service_interface='android.app.IActivityTaskManager')
ServiceInfo(service_name='trust', service_interface='android.app.trust.ITrustManager')
ServiceInfo(service_name='platform_compat', service_interface='com.android.internal.compat.IPlatformCompat')
ServiceInfo(service_name='platform_compat_native', service_interface='com.android.internal.compat.IPlatformCompatNative')
ServiceInfo(service_name='wifi', service_interface='android.net.wifi.IWifiManager')
ServiceInfo(service_name='nearby', service_interface='android.nearby.INearbyManager')
ServiceInfo(service_name='usb', service_interface='android.hardware.usb.IUsbManager')
ServiceInfo(service_name='sensor_privacy', service_interface='android.hardware.ISensorPrivacyManager')
ServiceInfo(service_name='mount', service_interface='android.os.storage.IStorageManager')
ServiceInfo(service_name='input', service_interface='android.hardware.input.IInputManager')
ServiceInfo(service_name='bugreport', service_interface='android.os.IDumpstate')
ServiceInfo(service_name='attestation_verification', service_interface='android.security.attestationverification.IAttestationVerificationManagerService')
ServiceInfo(service_name='safety_center', service_interface='android.safetycenter.ISafetyCenterManager')
ServiceInfo(service_name='activity', service_interface='android.app.IActivityManager')
ServiceInfo(service_name='appops', service_interface='com.android.internal.app.IAppOpsService')
ServiceInfo(service_name='SurfaceFlinger', service_interface='android.ui.ISurfaceComposer')
ServiceInfo(service_name='SurfaceFlingerAIDL', service_interface='android.gui.ISurfaceComposer')
ServiceInfo(service_name='face', service_interface='android.hardware.face.IFaceService')
ServiceInfo(service_name='uri_grants', service_interface='android.app.IUriGrantsManager')
ServiceInfo(service_name='dreams', service_interface='android.service.dreams.IDreamManager')
ServiceInfo(service_name='companiondevice', service_interface='android.companion.ICompanionDeviceManager')
ServiceInfo(service_name='people', service_interface='android.app.people.IPeopleManager')
ServiceInfo(service_name='vibrator_manager', service_interface='android.os.IVibratorManagerService')
ServiceInfo(service_name='vpn_management', service_interface='android.net.IVpnManager')
ServiceInfo(service_name='ambient_context', service_interface='android.app.ambientcontext.IAmbientContextManager')
ServiceInfo(service_name='media_projection', service_interface='android.media.projection.IMediaProjectionManager')
ServiceInfo(service_name='input_method', service_interface='com.android.internal.view.IInputMethodManager')
ServiceInfo(service_name='speech_recognition', service_interface='android.speech.IRecognitionServiceManager')
ServiceInfo(service_name='uimode', service_interface='android.app.IUiModeManager')
ServiceInfo(service_name='performance_hint', service_interface='android.os.IHintManager')
ServiceInfo(service_name='cloudsearch', service_interface='android.app.cloudsearch.ICloudSearchManager')
ServiceInfo(service_name='time_zone_detector', service_interface='android.app.timezonedetector.ITimeZoneDetectorService')
ServiceInfo(service_name='permissionmgr', service_interface='android.permission.IPermissionManager')
ServiceInfo(service_name='media_resource_monitor', service_interface='android.media.IMediaResourceMonitor')
ServiceInfo(service_name='media_session', service_interface='android.media.session.ISessionManager')
ServiceInfo(service_name='wallpaper_effects_generation', service_interface='android.app.wallpapereffectsgeneration.IWallpaperEffectsGenerationManager')
ServiceInfo(service_name='netstats', service_interface='android.net.INetworkStatsService')
ServiceInfo(service_name='pac_proxy', service_interface='android.net.IPacProxyManager')
ServiceInfo(service_name='fingerprint', service_interface='android.hardware.fingerprint.IFingerprintService')
ServiceInfo(service_name='time_detector', service_interface='android.app.timedetector.ITimeDetectorService')
ServiceInfo(service_name='domain_verification', service_interface='android.content.pm.verify.domain.IDomainVerificationManager')
ServiceInfo(service_name='device_identifiers', service_interface='android.os.IDeviceIdentifiersPolicyService')
ServiceInfo(service_name='package', service_interface='android.content.pm.IPackageManager')
ServiceInfo(service_name='android.security.identity', service_interface='android.security.identity.ICredentialStoreFactory')
ServiceInfo(service_name='telecom', service_interface='com.android.internal.telecom.ITelecomService')
ServiceInfo(service_name='texttospeech', service_interface='android.speech.tts.ITextToSpeechManager')
ServiceInfo(service_name='power', service_interface='android.os.IPowerManager')
ServiceInfo(service_name='device_policy', service_interface='android.app.admin.IDevicePolicyManager')
ServiceInfo(service_name='autofill', service_interface='android.view.autofill.IAutoFillManager')
ServiceInfo(service_name='app_hibernation', service_interface='android.apphibernation.IAppHibernationService')
ServiceInfo(service_name='search', service_interface='android.app.ISearchManager')
ServiceInfo(service_name='locale', service_interface='android.app.ILocaleManager')
ServiceInfo(service_name='game', service_interface='android.app.IGameManagerService')
ServiceInfo(service_name='media.audio_flinger', service_interface='android.media.IAudioFlingerService')
ServiceInfo(service_name='media.audio_policy', service_interface='android.media.IAudioPolicyService')
ServiceInfo(service_name='media.camera', service_interface='android.hardware.ICameraService')
ServiceInfo(service_name='drm.drmManager', service_interface='drm.IDrmManagerService')
ServiceInfo(service_name='media.extractor', service_interface='android.IMediaExtractorService')
ServiceInfo(service_name='media.metrics', service_interface='android.media.IMediaMetricsService')
ServiceInfo(service_name='media.player', service_interface='android.media.IMediaPlayerService')
ServiceInfo(service_name='media.resource_manager', service_interface='android.media.IResourceManagerService')
ServiceInfo(service_name='media.resource_observer', service_interface='android.media.IResourceObserverService')
ServiceInfo(service_name='carrier_config', service_interface='com.android.internal.telephony.ICarrierConfigLoader')
ServiceInfo(service_name='ions', service_interface='com.android.internal.telephony.IOns')
ServiceInfo(service_name='iphonesubinfo', service_interface='com.android.internal.telephony.IPhoneSubInfo')
ServiceInfo(service_name='isms', service_interface='com.android.internal.telephony.ISms')
ServiceInfo(service_name='isub', service_interface='com.android.internal.telephony.ISub')
ServiceInfo(service_name='phone', service_interface='com.android.internal.telephony.ITelephony')
ServiceInfo(service_name='simphonebook', service_interface='com.android.internal.telephony.IIccPhoneBook')
ServiceInfo(service_name='telephony_ims', service_interface='android.telephony.ims.aidl.IImsRcsController')
Can access fallback: False

untrusted_app can access hwservice:
ServiceInfo(service_name='android.hardware.drm.IDrmFactory/clearkey', service_interface='android.hardware.drm.IDrmFactory')
ServiceInfo(service_name='android.hardware.graphics.allocator.IAllocator/default', service_interface='android.hardware.graphics.allocator.IAllocator')
ServiceInfo(service_name='android.hardware.neuralnetworks.IDevice/nnapi-sample_all', service_interface='android.hardware.neuralnetworks.IDevice')
ServiceInfo(service_name='android.hardware.neuralnetworks.IDevice/nnapi-sample_float_fast', service_interface='android.hardware.neuralnetworks.IDevice')
ServiceInfo(service_name='android.hardware.neuralnetworks.IDevice/nnapi-sample_float_slow', service_interface='android.hardware.neuralnetworks.IDevice')
ServiceInfo(service_name='android.hardware.neuralnetworks.IDevice/nnapi-sample_minimal', service_interface='android.hardware.neuralnetworks.IDevice')
ServiceInfo(service_name='android.hardware.neuralnetworks.IDevice/nnapi-sample_quant', service_interface='android.hardware.neuralnetworks.IDevice')
ServiceInfo(service_name='android.hardware.neuralnetworks.IDevice/nnapi-sample_sl_shim', service_interface='android.hardware.neuralnetworks.IDevice')
Can access fallback: False

accessible files
/data/anr(/.*)?: {'open', 'append'}
/data/misc/apexdata/com\.android\.art(/.*)?: {'read', 'open', 'map', 'lock', 'execute', 'ioctl', 'execute_no_trans', 'watch_reads', 'watch', 'getattr'}
/data/app(/.*)?: {'read', 'open', 'map', 'lock', 'execute', 'ioctl', 'execute_no_trans', 'watch_reads', 'watch', 'getattr'}
/mnt/expand/[^/]+/app(/.*)?: {'read', 'open', 'map', 'lock', 'execute', 'ioctl', 'execute_no_trans', 'watch_reads', 'watch', 'getattr'}
/data/rollback/\d+/[^/]+/.*\.apk: {'read', 'open', 'map', 'lock', 'execute', 'ioctl', 'execute_no_trans', 'watch_reads', 'watch', 'getattr'}
/data/incremental(/.*)?: {'read', 'open', 'map', 'lock', 'execute', 'ioctl', 'execute_no_trans', 'watch_reads', 'watch', 'getattr'}
/data/backup(/.*)?: {'map', 'read', 'write', 'getattr'}
/data/system_ce/[0-9]+/backup(/.*)?: {'map', 'read', 'write', 'getattr'}
/data/system_ce/[0-9]+/backup_stage(/.*)?: {'map', 'read', 'write', 'getattr'}
/data/secure/backup(/.*)?: {'map', 'read', 'write', 'getattr'}
/cache/backup_stage(/.*)?: {'map', 'read', 'write', 'getattr'}
/data/cache/backup_stage(/.*)?: {'map', 'read', 'write', 'getattr'}
/data/app/[^/]+/oat(/.*)?: {'read', 'open', 'map', 'execute', 'ioctl', 'lock', 'watch_reads', 'watch', 'getattr'}
/data/app/[^/]+/[^/]+/oat(/.*)?: {'read', 'open', 'map', 'execute', 'ioctl', 'lock', 'watch_reads', 'watch', 'getattr'}
/mnt/expand/[^/]+/app/[^/]+/oat(/.*)?: {'read', 'open', 'map', 'execute', 'ioctl', 'lock', 'watch_reads', 'watch', 'getattr'}
/mnt/expand/[^/]+/app/[^/]+/[^/]+/oat(/.*)?: {'read', 'open', 'map', 'execute', 'ioctl', 'lock', 'watch_reads', 'watch', 'getattr'}
/mnt/expand/[^/]+/app/vmdl[^/]+\.tmp/oat(/.*)?: {'read', 'open', 'map', 'execute', 'ioctl', 'lock', 'watch_reads', 'watch', 'getattr'}
/data/app/vmdl[^/]+\.tmp/oat(/.*)?: {'read', 'open', 'map', 'execute', 'ioctl', 'lock', 'watch_reads', 'watch', 'getattr'}
/data/dalvik-cache(/.*)?: {'read', 'open', 'map', 'execute', 'ioctl', 'lock', 'watch_reads', 'watch', 'getattr'}
/data/system/dropbox(/.*)?: {'read', 'getattr'}
/data/fonts/files(/.*)?: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/data/system/heapdump(/.*)?: {'append'}
/data/system/users/[0-9]+/photo\.png: {'map', 'read', 'getattr'}
/data/misc/keychain(/.*)?: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/system/bin/logcat (exact): {'read', 'open', 'map', 'lock', 'execute', 'ioctl', 'execute_no_trans', 'watch_reads', 'watch', 'getattr'}
/system/bin/logcatd (exact): {'read', 'open', 'map', 'lock', 'execute', 'ioctl', 'execute_no_trans', 'watch_reads', 'watch', 'getattr'}
/data/misc/trace(/.*)?: {'open', 'map', 'lock', 'write', 'create', 'append'}
/data/misc/user(/.*)?: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/oem(/.*)?: {'read', 'open', 'map', 'lock', 'execute', 'ioctl', 'execute_no_trans', 'watch_reads', 'watch', 'getattr'}
/data/resource-cache(/.*)?: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/data/system_de/[0-9]+/ringtones(/.*)?: {'map', 'read', 'write', 'getattr'}
/system/bin/run-as (exact): {'getattr'}
/(odm|vendor/odm)/lib(64)?/egl(/.*)?: {'read', 'open', 'map', 'execute', 'getattr'}
/(vendor|system/vendor)/lib(64)?/egl(/.*)?: {'read', 'open', 'map', 'execute', 'getattr'}
/(vendor|system/vendor)/lib(64)?/libhwbinder.so: {'read', 'open', 'map', 'execute', 'getattr'}
/(vendor|system/vendor)/lib(64)?/libhidltransport.so: {'read', 'open', 'map', 'execute', 'getattr'}
/(vendor|system/vendor)/lib(64)?/hw/gralloc\.default\.so: {'read', 'open', 'map', 'execute', 'getattr'}
/(vendor|system/vendor)/lib(64)?/hw/android\.hardware\.renderscript@1\.0-impl\.so: {'read', 'open', 'map', 'execute', 'getattr'}
/(vendor|system/vendor)/lib(64)?/hw/android\.hardware\.graphics\.mapper@2\.0-impl\.so: {'read', 'open', 'map', 'execute', 'getattr'}
/(vendor|system/vendor)/lib(64)?/hw/android\.hardware\.graphics\.mapper@3\.0-impl\.so: {'read', 'open', 'map', 'execute', 'getattr'}
/(vendor|system/vendor)/lib(64)?/hw/android\.hardware\.graphics\.mapper@4\.0-impl\.so: {'read', 'open', 'map', 'execute', 'getattr'}
/(vendor|system/vendor)/lib(64)?/hw/android\.hardware\.graphics\.mapper@2\.0-impl-2\.1\.so: {'read', 'open', 'map', 'execute', 'getattr'}
/vendor/lib(64)?/dri/.*: {'read', 'open', 'map', 'execute', 'getattr'}
/vendor/lib(64)?/libdrm.so: {'read', 'open', 'map', 'execute', 'getattr'}
/vendor/lib(64)?/libglapi.so: {'read', 'open', 'map', 'execute', 'getattr'}
/vendor/lib(64)?/vsoc_lib.so: {'read', 'open', 'map', 'execute', 'getattr'}
/vendor/lib(64)?/libEGL_angle\.so: {'read', 'open', 'map', 'execute', 'getattr'}
/vendor/lib(64)?/libGLESv1_enc\.so: {'read', 'open', 'map', 'execute', 'getattr'}
/vendor/lib(64)?/libGLESv2_enc\.so: {'read', 'open', 'map', 'execute', 'getattr'}
/vendor/lib(64)?/libvulkan_enc\.so: {'read', 'open', 'map', 'execute', 'getattr'}
/vendor/lib(64)?/libandroidemu\.so: {'read', 'open', 'map', 'execute', 'getattr'}
/vendor/lib(64)?/libGLESv2_angle\.so: {'read', 'open', 'map', 'execute', 'getattr'}
/vendor/lib(64)?/hw/vulkan.pastel.so: {'read', 'open', 'map', 'execute', 'getattr'}
/vendor/lib(64)?/libcuttlefish_fs.so: {'read', 'open', 'map', 'execute', 'getattr'}
/vendor/lib(64)?/hw/vulkan\.ranchu\.so: {'read', 'open', 'map', 'execute', 'getattr'}
/vendor/lib(64)?/libEGL_emulation\.so: {'read', 'open', 'map', 'execute', 'getattr'}
/vendor/lib(64)?/libminigbm_gralloc.so: {'read', 'open', 'map', 'execute', 'getattr'}
/vendor/lib(64)?/libGLESv1_CM_angle\.so: {'read', 'open', 'map', 'execute', 'getattr'}
/vendor/lib(64)?/libGLESv2_emulation\.so: {'read', 'open', 'map', 'execute', 'getattr'}
/vendor/lib(64)?/libGoldfishProfiler\.so: {'read', 'open', 'map', 'execute', 'getattr'}
/vendor/lib(64)?/libOpenglCodecCommon\.so: {'read', 'open', 'map', 'execute', 'getattr'}
/vendor/lib(64)?/libOpenglSystemCommon\.so: {'read', 'open', 'map', 'execute', 'getattr'}
/vendor/lib(64)?/lib_renderControl_enc\.so: {'read', 'open', 'map', 'execute', 'getattr'}
/vendor/lib(64)?/libGLESv1_CM_emulation\.so: {'read', 'open', 'map', 'execute', 'getattr'}
/vendor/lib(64)?/libfeature_support_angle\.so: {'read', 'open', 'map', 'execute', 'getattr'}
/vendor/lib(64)?/libminigbm_gralloc4_utils.so: {'read', 'open', 'map', 'execute', 'getattr'}
/vendor/lib(64)?/hw/android\.hardware\.health@2\.0-impl-2\.1-cuttlefish\.so: {'read', 'open', 'map', 'execute', 'getattr'}
/vendor/lib(64)?/hw/android\.hardware\.graphics\.mapper@4\.0-impl\.minigbm\.so: {'read', 'open', 'map', 'execute', 'getattr'}
/data/misc/shared_relro(/.*)?: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/mnt/expand/[^/]+/local/tmp(/.*)?: {'read', 'open', 'map', 'lock', 'ioctl', 'write', 'watch_reads', 'watch', 'getattr'}
/data/local/tmp(/.*)?: {'read', 'open', 'map', 'lock', 'ioctl', 'write', 'watch_reads', 'watch', 'getattr'}
/data/system_ce/[0-9]+/shortcut_service/bitmaps(/.*)?: {'map', 'read', 'getattr'}
/data/(.*)?: {'map', 'read', 'getattr'}
/mnt/expand/[^/]+(/.*)?: {'map', 'read', 'getattr'}
/(product|system/product)(/.*)?: {'read', 'open', 'map', 'execute', 'execute_no_trans', 'getattr'}
/(system_ext|system/system_ext)(/.*)?: {'read', 'open', 'map', 'execute', 'execute_no_trans', 'getattr'}
/(product|system/product)/overlay(/.*)?: {'read', 'open', 'map', 'execute', 'execute_no_trans', 'getattr'}
/system(/.*)?: {'read', 'open', 'map', 'execute', 'execute_no_trans', 'getattr'}
/cache/overlay/(system|product)/upper: {'read', 'open', 'map', 'execute', 'execute_no_trans', 'getattr'}
/mnt/scratch/overlay/(system|product)/upper: {'read', 'open', 'map', 'execute', 'execute_no_trans', 'getattr'}
/system/bin/logwrapper: {'read', 'open', 'map', 'execute', 'execute_no_trans', 'getattr'}
/data/tombstones(/.*)?: {'read', 'getattr'}
/data/misc/profiles/ref(/.*)?: {'read', 'watch', 'unlink', 'open', 'setattr', 'map', 'lock', 'ioctl', 'write', 'create', 'watch_reads', 'rename', 'append', 'getattr'}
/data/misc/profiles/cur/[0-9]+/.*: {'read', 'watch', 'unlink', 'open', 'setattr', 'map', 'lock', 'ioctl', 'write', 'create', 'watch_reads', 'rename', 'append', 'getattr'}
/(odm|vendor/odm)/framework(/.*)?: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/(vendor|system/vendor)/framework(/.*)?: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/(odm|vendor/odm)/overlay(/.*)?: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/(vendor|system/vendor)/overlay(/.*)?: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/(system_ext|system/system_ext)/overlay(/.*)?: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/oem/overlay(/.*)?: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/data/system/users/[0-9]+/wallpaper: {'map', 'read', 'write', 'getattr'}
/data/system/users/[0-9]+/wallpaper_lock: {'map', 'read', 'write', 'getattr'}
/data/system/users/[0-9]+/wallpaper_orig: {'map', 'read', 'write', 'getattr'}
/data/system/users/[0-9]+/wallpaper_lock_orig: {'map', 'read', 'write', 'getattr'}
/system/bin/app_process32: {'read', 'open', 'map', 'lock', 'execute', 'ioctl', 'execute_no_trans', 'watch_reads', 'watch', 'getattr'}
/system/bin/app_process64: {'read', 'open', 'map', 'lock', 'execute', 'ioctl', 'execute_no_trans', 'watch_reads', 'watch', 'getattr'}
/dev/cgroup_info(/.*)?: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/cores(/.*)?: {'read', 'watch', 'unlink', 'open', 'setattr', 'map', 'lock', 'ioctl', 'write', 'create', 'watch_reads', 'rename', 'append', 'getattr'}
/dev/cpu_variant:.*: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/linkerconfig(/.*)?: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/(odm|vendor/odm)/etc/selinux/odm_property_contexts: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/(product|system/product)/etc/selinux/product_property_contexts: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/(system_ext|system/system_ext)/etc/selinux/system_ext_property_contexts: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/plat_property_contexts: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/vendor_property_contexts: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/product_property_contexts: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/dev/selinux/apex_property_contexts: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/system/etc/selinux/plat_property_contexts: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/dev/__properties__/property_info: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/system/etc/event-log-tags: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/(product|system/product)/etc/group: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/(system_ext|system/system_ext)/etc/group: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/system/etc/group: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/(product|system/product)/lib(64)?(/.*)?: {'read', 'open', 'map', 'execute', 'getattr'}
/(system_ext|system/system_ext)/lib(64)?(/.*)?: {'read', 'open', 'map', 'execute', 'getattr'}
/system/lib(64)?(/.*)?: {'read', 'open', 'map', 'execute', 'getattr'}
/system/etc/ld\.config.*: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/system/bin/linker(64)?: {'read', 'open', 'map', 'execute', 'execute_no_trans', 'getattr'}
/system/bin/bootstrap/linker(64)?: {'read', 'open', 'map', 'execute', 'execute_no_trans', 'getattr'}
/(product|system/product)/etc/passwd: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/(system_ext|system/system_ext)/etc/passwd: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/system/etc/passwd: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/system/etc/seccomp_policy(/.*)?: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/system/etc/security/cacerts(/.*)?: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/system/usr/share/zoneinfo(/.*)?: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/system/etc/task_profiles/task_profiles_[0-9]+\.json: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/system/etc/task_profiles\.json: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/(odm|vendor/odm)/etc(/.*)?: {'map', 'read', 'open', 'getattr'}
/(vendor|system/vendor)/etc(/.*)?: {'map', 'read', 'open', 'getattr'}
/(vendor|system/vendor)/manifest\.xml: {'map', 'read', 'open', 'getattr'}
/(vendor|system/vendor)/etc/vintf(/.*)?: {'map', 'read', 'open', 'getattr'}
/(vendor|system/vendor)/compatibility_matrix\.xml: {'map', 'read', 'open', 'getattr'}
/(odm_dlkm|vendor/odm_dlkm|system/vendor/odm_dlkm)/etc(/.*)?: {'map', 'read', 'open', 'getattr'}
/(vendor_dlkm|vendor/vendor_dlkm|system/vendor/vendor_dlkm)/etc(/.*)?: {'map', 'read', 'open', 'getattr'}
/(vendor|system/vendor)/etc/task_profiles\.json: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/(odm|vendor/odm)/lib(64)?/vndk-sp(/.*)?: {'read', 'open', 'map', 'execute', 'getattr'}
/(vendor|system/vendor)/lib(64)?/vndk-sp(/.*)?: {'read', 'open', 'map', 'execute', 'getattr'}
/data/misc/zoneinfo(/.*)?: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/data/media(/.*)?: {'read', 'watch', 'unlink', 'open', 'setattr', 'map', 'lock', 'ioctl', 'write', 'create', 'watch_reads', 'rename', 'append', 'getattr'}
/mnt/expand/[^/]+/media(/.*)?: {'read', 'watch', 'unlink', 'open', 'setattr', 'map', 'lock', 'ioctl', 'write', 'create', 'watch_reads', 'rename', 'append', 'getattr'}
/data/misc/sms(/.*)?: {'read', 'write', 'getattr'}
/data/misc/apns(/.*)?: {'read', 'write', 'getattr'}
/data/misc/carrierid(/.*)?: {'read', 'write', 'getattr'}
/system/bin/sh (exact): {'read', 'open', 'map', 'lock', 'execute', 'ioctl', 'execute_no_trans', 'watch_reads', 'watch', 'getattr'}
/system/bin/simpleperf: {'read', 'open', 'map', 'execute', 'getattr'}
/data/misc/textclassifier(/.*)?: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/system/bin/toybox (exact): {'read', 'open', 'map', 'lock', 'execute', 'ioctl', 'execute_no_trans', 'watch_reads', 'watch', 'getattr'}
/system/bin/toolbox (exact): {'read', 'open', 'map', 'lock', 'execute', 'ioctl', 'execute_no_trans', 'watch_reads', 'watch', 'getattr'}
/system/bin/mini-keyctl (exact): {'read', 'open', 'map', 'lock', 'execute', 'ioctl', 'execute_no_trans', 'watch_reads', 'watch', 'getattr'}
/(odm|vendor/odm)/app(/.*)?: {'read', 'open', 'map', 'execute', 'ioctl', 'lock', 'watch_reads', 'watch', 'getattr'}
/(odm|vendor/odm)/priv-app(/.*)?: {'read', 'open', 'map', 'execute', 'ioctl', 'lock', 'watch_reads', 'watch', 'getattr'}
/(vendor|system/vendor)/app(/.*)?: {'read', 'open', 'map', 'execute', 'ioctl', 'lock', 'watch_reads', 'watch', 'getattr'}
/(vendor|system/vendor)/priv-app(/.*)?: {'read', 'open', 'map', 'execute', 'ioctl', 'lock', 'watch_reads', 'watch', 'getattr'}
/data/app-private/vmdl.*\.tmp(/.*)?: {'read', 'getattr'}
/mnt/expand/[^/]+/app/vmdl[^/]+\.tmp(/.*)?: {'read', 'getattr'}
/data/app/vmdl[^/]+\.tmp(/.*)?: {'read', 'getattr'}
/mnt/asec(/.*)?: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/mnt/asec/[^/]+/[^/]+\.zip: {'execute'}
/mnt/asec/[^/]+/lib(/.*)?: {'execute'}
/data/preloads/demo(/.*)?: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/data/preloads/media(/.*)?: {'read', 'open', 'map', 'lock', 'ioctl', 'watch_reads', 'watch', 'getattr'}
/system/bin/bcc: {'read', 'open', 'map', 'execute', 'getattr'}
/system/bin/ld\.mc: {'read', 'open', 'map', 'execute', 'getattr'}
/data/local/traces(/.*)?: {'read', 'getattr'}
```

## Pulling Mathing Android Code
https://source.android.com/docs/setup/reference/build-numbers has a list mapping build IDs to branch names.
Build ID can be gotten in ADB shell from getprop ro.build.id.

Then clone with ```sh
repo init -u https://android.googlesource.com/platform/manifest -b <branch_name>
repo sync -j8
```
