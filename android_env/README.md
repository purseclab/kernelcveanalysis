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
untrusted_app can access:
android.security.apc
android.security.identity
android.hardware.drm.IDrmFactory/clearkey
android.hardware.drm.ICryptoFactory/clearkey
android.hardware.graphics.allocator.IAllocator/default
android.security.maintenance
android.system.keystore2.IKeystoreService/default
android.security.keystore
android.security.legacykeystore
Can access fallback: False

untrusted_app_all can access:
media.aaudio
media.audio_flinger
media.audio_policy
media.log
media.sound_trigger_hw
media.camera
drm.drmManager
media.drm
media.extractor
media.metrics
media.player
media.resource_manager
media.resource_observer
nfc
carrier_config
econtroller
euicc_card_controller
ions
iphonesubinfo_msim
iphonesubinfo2
iphonesubinfo
ims
ircsmessage
isms_msim
isms2
isms
isub
phone_msim
phone1
phone2
phone
radio.phonesubinfo
radio.phone
radio.sms
rcs
simphonebook_msim
simphonebook2
simphonebook
sip
telephony_ims
android.system.virtualizationservice
vrmanager
Can access fallback: False
```

## Pulling Mathing Android Code
https://source.android.com/docs/setup/reference/build-numbers has a list mapping build IDs to branch names.
Build ID can be gotten in ADB shell from getprop ro.build.id.

Then clone with ```sh
repo init -u https://android.googlesource.com/platform/manifest -b <branch_name>
repo sync -j8
```