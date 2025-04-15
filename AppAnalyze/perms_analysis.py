from androguard.core.bytecodes import apk
import os
import json
import re
from datetime import datetime
from collections import Counter, defaultdict
import matplotlib.pyplot as plt
import numpy as np

class PermissionAnalyzer:
    def __init__(self):
        self.reset_permissions()
        self.directory_stats = {
            "total_apps": 0,
            "successful_analyses": 0,
            "failed_analyses": 0,
            "apps_with_dangerous_perms": 0,
            "all_dangerous_perms": Counter()
        }

    def reset_permissions(self):
        """Reset permissions dictionary for new analysis"""
        self.permissions = {
            "dangerous": [],
            "normal": [],
            "signature": [],
            "signatureOrSystem": [],
            "others": []
        }

    def analyze_directory(self, directory="."):
        """Analyze all APK files in a directory"""
        results = {"apps": {}, "directory_summary": None}
        apk_files = [f for f in os.listdir(directory) if f.endswith('.apk')]
        
        if not apk_files:
            print("No APK files found in the specified directory.")
            return results
            
        self.directory_stats["total_apps"] = len(apk_files)
        print(f"Found {len(apk_files)} APK files to analyze.")
        
        for apk_file in apk_files:
            print(f"\nAnalyzing {apk_file}...")
            apk_path = os.path.join(directory, apk_file)
            try:
                self.reset_permissions()
                app_info = self.analyze_apk(apk_path)
                if app_info:
                    results["apps"][apk_file] = app_info
                    self.directory_stats["successful_analyses"] += 1
                    if app_info["permissions"]["dangerous"]:
                        self.directory_stats["apps_with_dangerous_perms"] += 1
                        self.directory_stats["all_dangerous_perms"].update(
                            app_info["permissions"]["dangerous"]
                        )
            except Exception as e:
                print(f"Error analyzing {apk_file}: {str(e)}")
                results["apps"][apk_file] = {"error": str(e)}
                self.directory_stats["failed_analyses"] += 1

        results["directory_summary"] = self.get_directory_summary()
        return results

    def analyze_apk(self, apk_path):
        """Analyze a single APK file"""
        a = apk.APK(apk_path)
        
        app_info = {
            "package_name": a.get_package(),
            "version_name": a.get_androidversion_name(),
            "version_code": a.get_androidversion_code(),
        }
        
        self.analyze_permissions(a.get_permissions())
        
        app_info["permissions"] = self.permissions.copy()
        app_info["permission_summary"] = self.get_permission_summary()
        
        return app_info

    def analyze_permissions(self, permissions):
        """Categorize permissions"""
        for perm in permissions:
            if perm.startswith("android.permission"):   
                permSuffix = perm[len("android.permission") + 1:]
                if permSuffix in self.DVM_PERMISSIONS["MANIFEST_PERMISSION"]:
                    permItem = self.DVM_PERMISSIONS["MANIFEST_PERMISSION"][permSuffix]
                    self.permissions[permItem[0]].append(permSuffix)     
                else:
                    self.permissions["others"].append(perm)
            elif perm.startswith("com.oculus.permission"):
                permSuffix = perm[len("com.oculus.permission") + 1:]
                if permSuffix in self.DVM_PERMISSIONS["MANIFEST_PERMISSION"]:
                    permItem = self.DVM_PERMISSIONS["MANIFEST_PERMISSION"][permSuffix]
                    self.permissions[permItem[0]].append(permSuffix)
                else:
                    self.permissions["others"].append(perm)
            else:
                self.permissions["others"].append(perm)

    def get_permission_summary(self):
        """Get summary of permission counts by category"""
        return {
            category: len(perms) 
            for category, perms in self.permissions.items()
        }

    def get_directory_summary(self):
        """Generate directory-wide summary statistics"""
        successful = self.directory_stats["successful_analyses"]
        if successful == 0:
            return {"error": "No successful analyses"}
            
        dangerous_perms = self.directory_stats["all_dangerous_perms"]
        
        return {
            "total_apps_analyzed": self.directory_stats["total_apps"],
            "successful_analyses": successful,
            "failed_analyses": self.directory_stats["failed_analyses"],
            "apps_with_dangerous_permissions": {
                "count": self.directory_stats["apps_with_dangerous_perms"],
                "percentage": round((self.directory_stats["apps_with_dangerous_perms"] / successful) * 100, 2)
            },
            "dangerous_permissions_usage": {
                "unique_count": len(dangerous_perms),
                "total_occurrences": sum(dangerous_perms.values()),
                "most_common": dangerous_perms.most_common()
            }
        }

    # Add your DVM_PERMISSIONS dictionary here
    DVM_PERMISSIONS = {
        'MANIFEST_PERMISSION': {
            'SEND_SMS': ['dangerous', 'send SMS messages',
                         'Allows application to send SMS messages. Malicious applications may cost you money by sending messages without your confirmation.'],
            'SEND_SMS_NO_CONFIRMATION': ['signatureOrSystem', 'send SMS messages',
                                         'send SMS messages via the Messaging app with no user input or confirmation'],
            'CALL_PHONE': ['dangerous', 'directly call phone numbers',
                           'Allows the application to call phone numbers without your intervention. Malicious applications may cause unexpected calls on your phone bill. Note that this does not allow the application to call emergency numbers.'],
            'RECEIVE_SMS': ['dangerous', 'receive SMS',
                            'Allows application to receive and process SMS messages. Malicious applications may monitor your messages or delete them without showing them to you.'],
            'RECEIVE_MMS': ['dangerous', 'receive MMS',
                            'Allows application to receive and process MMS messages. Malicious applications may monitor your messages or delete them without showing them to you.'],
            'READ_SMS': ['dangerous', 'read SMS or MMS',
                         'Allows application to read SMS messages stored on your phone or SIM card. Malicious applications may read your confidential messages.'],
            'WRITE_SMS': ['normal', 'edit SMS or MMS',
                          'Allows application to write to SMS messages stored on your phone or SIM card. Malicious applications may delete your messages.'],
            'RECEIVE_WAP_PUSH': ['dangerous', 'receive WAP',
                                 'Allows application to receive and process WAP messages. Malicious applications may monitor your messages or delete them without showing them to you.'],
            'READ_CONTACTS': ['dangerous', 'read contact data',
                              'Allows an application to read all of the contact (address) data stored on your phone. Malicious applications can use this to send your data to other people.'],
            'WRITE_CONTACTS': ['dangerous', 'write contact data',
                               'Allows an application to modify the contact (address) data stored on your phone. Malicious applications can use this to erase or modify your contact data.'],
            'READ_PROFILE': ['normal', 'read the user\'s personal profile data',
                             'Allows an application to read the user\'s personal profile data.'],
            'WRITE_PROFILE': ['normal', 'write the user\'s personal profile data',
                              'Allows an application to write (but not read) the user\'s personal profile data.'],
            'READ_SOCIAL_STREAM': ['normal', 'read from the user\'s social stream',
                                   'Allows an application to read from the user\'s social stream.'],
            'WRITE_SOCIAL_STREAM': ['normal', 'write the user\'s social stream',
                                    'Allows an application to write (but not read) the user\'s social stream data.'],
            'READ_CALENDAR': ['dangerous', 'read calendar events',
                              'Allows an application to read all of the calendar events stored on your phone. Malicious applications can use this to send your calendar events to other people.'],
            'WRITE_CALENDAR': ['dangerous', 'add or modify calendar events and send emails to guests',
                               'Allows an application to add or change the events on your calendar, which may send emails to guests. Malicious applications can use this to erase or modify your calendar events or to send emails to guests.'],
            'READ_USER_DICTIONARY': ['normal', 'read user-defined dictionary',
                                     'Allows an application to read any private words, names and phrases that the user may have stored in the user dictionary.'],
            'WRITE_USER_DICTIONARY': ['normal', 'write to user-defined dictionary',
                                      'Allows an application to write new words into the user dictionary.'],
            'READ_HISTORY_BOOKMARKS': ['normal', 'read Browser\'s history and bookmarks',
                                       'Allows the application to read all the URLs that the browser has visited and all of the browser\'s bookmarks.'],
            'WRITE_HISTORY_BOOKMARKS': ['normal', 'write Browser\'s history and bookmarks',
                                        'Allows an application to modify the browser\'s history or bookmarks stored on your phone. Malicious applications can use this to erase or modify your browser\'s data.'],
            'SET_ALARM': ['normal', 'set alarm in alarm clock',
                          'Allows the application to set an alarm in an installed alarm clock application. Some alarm clock applications may not implement this feature.'],
            'ACCESS_FINE_LOCATION': ['dangerous', 'fine (GPS) location',
                                     'Access fine location sources, such as the Global Positioning System on the phone, where available. Malicious applications can use this to determine where you are and may consume additional battery power.'],
            'ACCESS_COARSE_LOCATION': ['dangerous', 'coarse (network-based) location',
                                       'Access coarse location sources, such as the mobile network database, to determine an approximate phone location, where available. Malicious applications can use this to determine approximately where you are.'],
            'ACCESS_MOCK_LOCATION': ['signature', 'mock location sources for testing',
                                     'Create mock location sources for testing. Malicious applications can use this to override the location and/or status returned by real-location sources such as GPS or Network providers.'],
            'ACCESS_LOCATION_EXTRA_COMMANDS': ['normal', 'access extra location provider commands',
                                               'Access extra location provider commands. Malicious applications could use this to interfere with the operation of the GPS or other location sources.'],
            'INSTALL_LOCATION_PROVIDER': ['signatureOrSystem', 'permission to install a location provider',
                                          'Create mock location sources for testing. Malicious applications can use this to override the location and/or status returned by real-location sources such as GPS or Network providers, or monitor and report your location to an external source.'],
            'INTERNET': ['normal', 'full Internet access', 'Allows an application to create network sockets.'],
            'ACCESS_NETWORK_STATE': ['normal', 'view network status',
                                     'Allows an application to view the status of all networks.'],
            'ACCESS_WIFI_STATE': ['normal', 'view Wi-Fi status',
                                  'Allows an application to view the information about the status of Wi-Fi.'],
            'BLUETOOTH': ['normal', 'create Bluetooth connections',
                          'Allows an application to view configuration of the local Bluetooth phone and to make and accept connections with paired devices.'],
            'NFC': ['normal', 'control Near-Field Communication',
                    'Allows an application to communicate with Near-Field Communication (NFC) tags, cards and readers.'],
            'USE_SIP': ['dangerous', 'make/receive Internet calls',
                        'Allows an application to use the SIP service to make/receive Internet calls.'],
            'ACCOUNT_MANAGER': ['signature', 'act as the Account Manager Service',
                                'Allows an application to make calls to Account Authenticators'],
            'GET_ACCOUNTS': ['dangerous', 'discover known accounts',
                             'Allows an application to access the list of accounts known by the phone.'],
            'AUTHENTICATE_ACCOUNTS': ['normal', 'act as an account authenticator',
                                      'Allows an application to use the account authenticator capabilities of the Account Manager, including creating accounts as well as obtaining and setting their passwords.'],
            'USE_CREDENTIALS': ['normal', 'use the authentication credentials of an account',
                                'Allows an application to request authentication tokens.'],
            'MANAGE_ACCOUNTS': ['normal', 'manage the accounts list',
                                'Allows an application to perform operations like adding and removing accounts and deleting their password.'],
            'MODIFY_AUDIO_SETTINGS': ['normal', 'change your audio settings',
                                      'Allows application to modify global audio settings, such as volume and routing.'],
            'RECORD_AUDIO': ['dangerous', 'record audio', 'Allows application to access the audio record path.'],
            'CAMERA': ['dangerous', 'take pictures and videos',
                       'Allows application to take pictures and videos with the camera. This allows the application to collect images that the camera is seeing at any time.'],
            'VIBRATE': ['normal', 'control vibrator', 'Allows the application to control the vibrator.'],
            'FLASHLIGHT': ['normal', 'control flashlight', 'Allows the application to control the flashlight.'],
            'ACCESS_USB': ['signatureOrSystem', 'access USB devices', 'Allows the application to access USB devices.'],
            'HARDWARE_TEST': ['signature', 'test hardware',
                              'Allows the application to control various peripherals for the purpose of hardware testing.'],
            'PROCESS_OUTGOING_CALLS': ['dangerous', 'intercept outgoing calls',
                                       'Allows application to process outgoing calls and change the number to be dialled. Malicious applications may monitor, redirect or prevent outgoing calls.'],
            'MODIFY_PHONE_STATE': ['signatureOrSystem', 'modify phone status',
                                   'Allows the application to control the phone features of the device. An application with this permission can switch networks, turn the phone radio on and off and the like, without ever notifying you.'],
            'READ_PHONE_STATE': ['dangerous', 'read phone state and identity',
                                 'Allows the application to access the phone features of the device. An application with this permission can determine the phone number and serial number of this phone, whether a call is active, the number that call is connected to and so on.'],
            'WRITE_EXTERNAL_STORAGE': ['dangerous', 'read/modify/delete SD card contents',
                                       'Allows an application to write to the SD card.'],
            'READ_EXTERNAL_STORAGE': ['dangerous', 'read SD card contents',
                                      'Allows an application to read from SD Card.'],
            'WRITE_SETTINGS': ['dangerous', 'modify global system settings',
                               'Allows an application to modify the system\'s settings data. Malicious applications can corrupt your system\'s configuration.'],
            'WRITE_SECURE_SETTINGS': ['signatureOrSystem', 'modify secure system settings',
                                      'Allows an application to modify the system\'s secure settings data. Not for use by common applications.'],
            'WRITE_GSERVICES': ['signatureOrSystem', 'modify the Google services map',
                                'Allows an application to modify the Google services map. Not for use by common applications.'],
            'EXPAND_STATUS_BAR': ['normal', 'expand/collapse status bar',
                                  'Allows application to expand or collapse the status bar.'],
            'GET_TASKS': ['dangerous', 'retrieve running applications',
                          'Allows application to retrieve information about currently and recently running tasks. May allow malicious applications to discover private information about other applications.'],
            'REORDER_TASKS': ['normal', 'reorder applications running',
                              'Allows an application to move tasks to the foreground and background. Malicious applications can force themselves to the front without your control.'],
            'CHANGE_CONFIGURATION': ['dangerous', 'change your UI settings',
                                     'Allows an application to change the current configuration, such as the locale or overall font size.'],
            'RESTART_PACKAGES': ['normal', 'kill background processes',
                                 'Allows an application to kill background processes of other applications, even if memory is not low.'],
            'KILL_BACKGROUND_PROCESSES': ['normal', 'kill background processes',
                                          'Allows an application to kill background processes of other applications, even if memory is not low.'],
            'FORCE_STOP_PACKAGES': ['signature', 'force-stop other applications',
                                    'Allows an application to stop other applications forcibly.'],
            'DUMP': ['signatureOrSystem', 'retrieve system internal status',
                     'Allows application to retrieve internal status of the system. Malicious applications may retrieve a wide variety of private and secure information that they should never commonly need.'],
            'SYSTEM_ALERT_WINDOW': ['dangerous', 'display system-level alerts',
                                    'Allows an application to show system-alert windows. Malicious applications can take over the entire screen of the phone.'],
            'SET_ANIMATION_SCALE': ['dangerous', 'modify global animation speed',
                                    'Allows an application to change the global animation speed (faster or slower animations) at any time.'],
            'PERSISTENT_ACTIVITY': ['dangerous', 'make application always run',
                                    'Allows an application to make parts of itself persistent, so that the system can\'t use it for other applications.'],
            'GET_PACKAGE_SIZE': ['normal', 'measure application storage space',
                                 'Allows an application to retrieve its code, data and cache sizes'],
            'SET_PREFERRED_APPLICATIONS': ['signature', 'set preferred applications',
                                           'Allows an application to modify your preferred applications. This can allow malicious applications to silently change the applications that are run, spoofing your existing applications to collect private data from you.'],
            'RECEIVE_BOOT_COMPLETED': ['normal', 'automatically start at boot',
                                       'Allows an application to start itself as soon as the system has finished booting. This can make it take longer to start the phone and allow the application to slow down the overall phone by always running.'],
            'BROADCAST_STICKY': ['normal', 'send sticky broadcast',
                                 'Allows an application to send sticky broadcasts, which remain after the broadcast ends. Malicious applications can make the phone slow or unstable by causing it to use too much memory.'],
            'WAKE_LOCK': ['normal', 'prevent phone from sleeping',
                          'Allows an application to prevent the phone from going to sleep.'],
            'SET_WALLPAPER': ['normal', 'set wallpaper', 'Allows the application to set the system wallpaper.'],
            'SET_WALLPAPER_HINTS': ['normal', 'set wallpaper size hints',
                                    'Allows the application to set the system wallpaper size hints.'],
            'SET_TIME': ['signatureOrSystem', 'set time', 'Allows an application to change the phone\'s clock time.'],
            'SET_TIME_ZONE': ['dangerous', 'set time zone', 'Allows an application to change the phone\'s time zone.'],
            'MOUNT_UNMOUNT_FILESYSTEMS': ['dangerous', 'mount and unmount file systems',
                                          'Allows the application to mount and unmount file systems for removable storage.'],
            'MOUNT_FORMAT_FILESYSTEMS': ['dangerous', 'format external storage',
                                         'Allows the application to format removable storage.'],
            'ASEC_ACCESS': ['signature', 'get information on internal storage',
                            'Allows the application to get information on internal storage.'],
            'ASEC_CREATE': ['signature', 'create internal storage',
                            'Allows the application to create internal storage.'],
            'ASEC_DESTROY': ['signature', 'destroy internal storage',
                             'Allows the application to destroy internal storage.'],
            'ASEC_MOUNT_UNMOUNT': ['signature', 'mount/unmount internal storage',
                                   'Allows the application to mount/unmount internal storage.'],
            'ASEC_RENAME': ['signature', 'rename internal storage',
                            'Allows the application to rename internal storage.'],
            'DISABLE_KEYGUARD': ['dangerous', 'disable key lock',
                                 'Allows an application to disable the key lock and any associated password security. A legitimate example of this is the phone disabling the key lock when receiving an incoming phone call, then re-enabling the key lock when the call is finished.'],
            'READ_SYNC_SETTINGS': ['normal', 'read sync settings',
                                   'Allows an application to read the sync settings, such as whether sync is enabled for Contacts.'],
            'WRITE_SYNC_SETTINGS': ['normal', 'write sync settings',
                                    'Allows an application to modify the sync settings, such as whether sync is enabled for Contacts.'],
            'READ_SYNC_STATS': ['normal', 'read sync statistics',
                                'Allows an application to read the sync stats; e.g. the history of syncs that have occurred.'],
            'WRITE_APN_SETTINGS': ['signatureOrSystem', 'write Access Point Name settings',
                                   'Allows an application to modify the APN settings, such as Proxy and Port of any APN.'],
            'SUBSCRIBED_FEEDS_READ': ['normal', 'read subscribed feeds',
                                      'Allows an application to receive details about the currently synced feeds.'],
            'SUBSCRIBED_FEEDS_WRITE': ['normal', 'write subscribed feeds',
                                       'Allows an application to modify your currently synced feeds. This could allow a malicious application to change your synced feeds.'],
            'CHANGE_NETWORK_STATE': ['normal', 'change network connectivity',
                                     'Allows an application to change the state of network connectivity.'],
            'CHANGE_WIFI_STATE': ['normal', 'change Wi-Fi status',
                                  'Allows an application to connect to and disconnect from Wi-Fi access points and to make changes to configured Wi-Fi networks.'],
            'CHANGE_WIFI_MULTICAST_STATE': ['normal', 'allow Wi-Fi Multicast reception',
                                            'Allows an application to receive packets not directly addressed to your device. This can be useful when discovering services offered nearby. It uses more power than the non-multicast mode.'],
            'BLUETOOTH_ADMIN': ['normal', 'bluetooth administration',
                                'Allows an application to configure the local Bluetooth phone and to discover and pair with remote devices.'],
            'CLEAR_APP_CACHE': ['signatureOrSystem', 'delete all application cache data',
                                'Allows an application to free phone storage by deleting files in application cache directory. Access is usually very restricted to system process.'],
            'READ_LOGS': ['signatureOrSystem', 'read sensitive log data',
                          'Allows an application to read from the system\'s various log files. This allows it to discover general information about what you are doing with the phone, potentially including personal or private information.'],
            'SET_DEBUG_APP': ['signatureOrSystem', 'enable application debugging',
                              'Allows an application to turn on debugging for another application. Malicious applications can use this to kill other applications.'],
            'SET_PROCESS_LIMIT': ['signatureOrSystem', 'limit number of running processes',
                                  'Allows an application to control the maximum number of processes that will run. Never needed for common applications.'],
            'SET_ALWAYS_FINISH': ['signatureOrSystem', 'make all background applications close',
                                  'Allows an application to control whether activities are always finished as soon as they go to the background. Never needed for common applications.'],
            'SIGNAL_PERSISTENT_PROCESSES': ['signatureOrSystem', 'send Linux signals to applications',
                                            'Allows application to request that the supplied signal be sent to all persistent processes.'],
            'DIAGNOSTIC': ['signature', 'read/write to resources owned by diag',
                           'Allows an application to read and write to any resource owned by the diag group; for example, files in /dev. This could potentially affect system stability and security. This should ONLY be used for hardware-specific diagnostics by the manufacturer or operator.'],
            'STATUS_BAR': ['signatureOrSystem', 'disable or modify status bar',
                           'Allows application to disable the status bar or add and remove system icons.'],
            'STATUS_BAR_SERVICE': ['signature', 'status bar', 'Allows the application to be the status bar.'],
            'FORCE_BACK': ['signature', 'force application to close',
                           'Allows an application to force any activity that is in the foreground to close and go back. Should never be needed for common applications.'],
            'UPDATE_DEVICE_STATS': ['signatureOrSystem', 'modify battery statistics',
                                    'Allows the modification of collected battery statistics. Not for use by common applications.'],
            'INTERNAL_SYSTEM_WINDOW': ['signature', 'display unauthorised windows',
                                       'Allows the creation of windows that are intended to be used by the internal system user interface. Not for use by common applications.'],
            'MANAGE_APP_TOKENS': ['signature', 'manage application tokens',
                                  'Allows applications to create and manage their own tokens, bypassing their common Z-ordering. Should never be needed for common applications.'],
            'INJECT_EVENTS': ['signature', 'press keys and control buttons',
                              'Allows an application to deliver its own input events (key presses, etc.) to other applications. Malicious applications can use this to take over the phone.'],
            'SET_ACTIVITY_WATCHER': ['signature', 'monitor and control all application launching',
                                     'Allows an application to monitor and control how the system launches activities. Malicious applications may compromise the system completely. This permission is needed only for development, never for common phone usage.'],
            'SHUTDOWN': ['signatureOrSystem', 'partial shutdown',
                         'Puts the activity manager into a shut-down state. Does not perform a complete shut down.'],
            'STOP_APP_SWITCHES': ['signatureOrSystem', 'prevent app switches',
                                  'Prevents the user from switching to another application.'],
            'READ_INPUT_STATE': ['signature', 'record what you type and actions that you take',
                                 'Allows applications to watch the keys that you press even when interacting with another application (such as entering a password). Should never be needed for common applications.'],
            'BIND_INPUT_METHOD': ['signature', 'bind to an input method',
                                  'Allows the holder to bind to the top-level interface of an input method. Should never be needed for common applications.'],
            'BIND_WALLPAPER': ['signatureOrSystem', 'bind to wallpaper',
                               'Allows the holder to bind to the top-level interface of wallpaper. Should never be needed for common applications.'],
            'BIND_DEVICE_ADMIN': ['signature', 'interact with device admin',
                                  'Allows the holder to send intents to a device administrator. Should never be needed for common applications.'],
            'SET_ORIENTATION': ['signature', 'change screen orientation',
                                'Allows an application to change the rotation of the screen at any time. Should never be needed for common applications.'],
            'INSTALL_PACKAGES': ['signatureOrSystem', 'directly install applications',
                                 'Allows an application to install new or updated Android packages. Malicious applications can use this to add new applications with arbitrarily powerful permissions.'],
            'REQUEST_INSTALL_PACKAGES': ['signature', 'Allows an application to request installing packages.',
                                         'Malicious applications can use this to try and trick users into installing additional malicious packages.'],
            'CLEAR_APP_USER_DATA': ['signature', 'delete other applications\' data',
                                    'Allows an application to clear user data.'],
            'DELETE_CACHE_FILES': ['signatureOrSystem', 'delete other applications\' caches',
                                   'Allows an application to delete cache files.'],
            'DELETE_PACKAGES': ['signatureOrSystem', 'delete applications',
                                'Allows an application to delete Android packages. Malicious applications can use this to delete important applications.'],
            'MOVE_PACKAGE': ['signature', 'Move application resources',
                             'Allows an application to move application resources from internal to external media and vice versa.'],
            'CHANGE_COMPONENT_ENABLED_STATE': ['signature', 'enable or disable application components',
                                               'Allows an application to change whether or not a component of another application is enabled. Malicious applications can use this to disable important phone capabilities. It is important to be careful with permission, as it is possible to bring application components into an unusable, inconsistent or unstable state.'],
            'ACCESS_SURFACE_FLINGER': ['signature', 'access SurfaceFlinger',
                                       'Allows application to use SurfaceFlinger low-level features.'],
            'READ_FRAME_BUFFER': ['signature', 'read frame buffer',
                                  'Allows application to read the content of the frame buffer.'],
            'BRICK': ['signature', 'permanently disable phone',
                      'Allows the application to disable the entire phone permanently. This is very dangerous.'],
            'REBOOT': ['signature', 'force phone reboot',
                       'Allows the application to force the phone to reboot.'],
            'DEVICE_POWER': ['signature', 'turn phone on or off',
                             'Allows the application to turn the phone on or off.'],
            'FACTORY_TEST': ['signature', 'run in factory test mode',
                             'Run as a low-level manufacturer test, allowing complete access to the phone hardware. Only available when a phone is running in manufacturer test mode.'],
            'BROADCAST_PACKAGE_REMOVED': ['signature', 'send package removed broadcast',
                                          'Allows an application to broadcast a notification that an application package has been removed. Malicious applications may use this to kill any other application running.'],
            'BROADCAST_SMS': ['signature', 'send SMS-received broadcast',
                              'Allows an application to broadcast a notification that an SMS message has been received. Malicious applications may use this to forge incoming SMS messages.'],
            'BROADCAST_WAP_PUSH': ['signature', 'send WAP-PUSH-received broadcast',
                                   'Allows an application to broadcast a notification that a WAP-PUSH message has been received. Malicious applications may use this to forge MMS message receipt or to replace the content of any web page silently with malicious variants.'],
            'MASTER_CLEAR': ['signature', 'reset system to factory defaults',
                             'Allows an application to completely reset the system to its factory settings, erasing all data, configuration and installed applications.'],
            'CALL_PRIVILEGED': ['signature', 'directly call any phone numbers',
                                'Allows the application to call any phone number, including emergency numbers, without your intervention. Malicious applications may place unnecessary and illegal calls to emergency services.'],
            'PERFORM_CDMA_PROVISIONING': ['signature', 'directly start CDMA phone setup',
                                          'Allows the application to start CDMA provisioning. Malicious applications may start CDMA provisioning unnecessarily'],
            'CONTROL_LOCATION_UPDATES': ['signature', 'control location update notifications',
                                         'Allows enabling/disabling location update notifications from the radio. Not for use by common applications.'],
            'ACCESS_CHECKIN_PROPERTIES': ['signature', 'access check-in properties',
                                          'Allows read/write access to properties uploaded by the check-in service. Not for use by common applications.'],
            'PACKAGE_USAGE_STATS': ['signature', 'update component usage statistics',
                                    'Allows the modification of collected component usage statistics. Not for use by common applications.'],
            'BATTERY_STATS': ['signature', 'modify battery statistics',
                              'Allows the modification of collected battery statistics. Not for use by common applications.'],
            'BACKUP': ['signature', 'control system back up and restore',
                       'Allows the application to control the system\'s back-up and restore mechanism. Not for use by common applications.'],
            'BIND_APPWIDGET': ['signature', 'choose widgets',
                               'Allows the application to tell the system which widgets can be used by which application. With this permission, applications can give access to personal data to other applications. Not for use by common applications.'],
            'CHANGE_BACKGROUND_DATA_SETTING': ['signature', 'change background data usage setting',
                                               'Allows an application to change the background data usage setting.'],
            'GLOBAL_SEARCH': ['signature', '', ''],
            'GLOBAL_SEARCH_CONTROL': ['signature', '', ''],
            'SET_WALLPAPER_COMPONENT': ['signature', '', ''],

            'ACCESS_CACHE_FILESYSTEM': ['signature', 'access the cache file system',
                                        'Allows an application to read and write the cache file system.'],
            'BLUETOOTH_ADVERTISE': ['dangerous', 'access the cache file system',
                                        'Allows an application to read and write the cache file system.'],
            'BLUETOOTH_CONNECT': ['dangerous', 'access the cache file system',
                                        'Allows an application to read and write the cache file system.'],
            'BLUETOOTH_SCAN': ['dangerous', 'access the cache file system',
                                        'Allows an application to read and write the cache file system.'],
            'UWB_RANGING': ['dangerous', 'access the cache file system',
                                        'Allows an application to read and write the cache file system.'],   
            'COPY_PROTECTED_DATA': ['signature',
                                    'Allows to invoke default container service to copy content. Not for use by common applications.',
                                    'Allows to invoke default container service to copy content. Not for use by common applications.'],
            'C2D_MESSAGE': ['signature', 'Allows cloud to device messaging',
                            'Allows the application to receive push notifications.'],
            'RECEIVE': ['signature', 'C2DM permissions', 'Permission for cloud to device messaging.'],
            'ADD_VOICEMAIL': ['dangerous', 'add voicemails into the system',
                              'Allows an application to add voicemails into the system.'],
            'ACCEPT_HANDOVER': ['dangerous', '',
                                'Allows a calling app to continue a call which was started in another app.  An example is a video calling app that wants to continue a voice call on the user\'s mobile network.'],
            'ACCESS_NOTIFICATION_POLICY': ['normal', '',
                                           'Marker permission for applications that wish to access notification policy.'],
            'ANSWER_PHONE_CALLS': ['dangerous', '', 'Allows the app to answer an incoming phone call.'],
            'BIND_ACCESSIBILITY_SERVICE': ['signature', '',
                                           'Must be required by an AccessibilityService, to ensure that only the system can bind to it.'],
            'BIND_AUTOFILL_SERVICE': ['signature', '',
                                      'Must be required by a AutofillService, to ensure that only the system can bind to it.'],
            'BIND_CARRIER_MESSAGING_SERVICE': ['signature', '',
                                               'The system process that is allowed to bind to services in carrier apps will have this permission.'],
            'BIND_CARRIER_SERVICES': ['signature', '',
                                      'The system process that is allowed to bind to services in carrier apps will have this permission. Carrier apps should use this permission to protect their services that only the system is allowed to bind to.'],
            'BIND_CHOOSER_TARGET_SERVICE': ['signature', '',
                                            'Must be required by a ChooserTargetService, to ensure that only the system can bind to it'],
            'BIND_CONDITION_PROVIDER_SERVICE': ['signature', '',
                                                'Must be required by a ConditionProviderService, to ensure that only the system can bind to it'],
            'BIND_DREAM_SERVICE': ['signature', '',
                                   'Must be required by an DreamService, to ensure that only the system can bind to it.'],
            'BIND_INCALL_SERVICE': ['signature', '',
                                    'Must be required by a InCallService, to ensure that only the system can bind to it.'],
            'BIND_MIDI_DEVICE_SERVICE': ['signature', '',
                                         'Must be required by an MidiDeviceService, to ensure that only the system can bind to it.'],
            'BIND_NFC_SERVICE': ['signature', '',
                                 'Must be required by a HostApduService or OffHostApduService to ensure that only the system can bind to it.'],
            'BIND_NOTIFICATION_LISTENER_SERVICE': ['signature', '',
                                                   'Must be required by an NotificationListenerService, to ensure that only the system can bind to it.'],
            'BIND_PRINT_SERVICE': ['signature', '',
                                   'Must be required by a PrintService, to ensure that only the system can bind to it.'],
            'BIND_QUICK_SETTINGS_TILE': ['signature', '',
                                         'Allows an application to bind to third party quick settings tiles.'],
            'BIND_REMOTEVIEWS': ['signature', '',
                                 'Must be required by a RemoteViewsService, to ensure that only the system can bind to it.'],
            'BIND_SCREENING_SERVICE': ['signature', '',
                                       'Must be required by a CallScreeningService, to ensure that only the system can bind to it.'],
            'BIND_TELECOM_CONNECTION_SERVICE': ['signature', '',
                                                'Must be required by a ConnectionService, to ensure that only the system can bind to it.'],
            'BIND_TEXT_SERVICE': ['signature', '',
                                  'Must be required by a TextService (e.g. SpellCheckerService) to ensure that only the system can bind to it.'],
            'BIND_TV_INPUT': ['signature', '',
                              'Must be required by a TvInputService to ensure that only the system can bind to it.'],
            'BIND_VISUAL_VOICEMAIL_SERVICE': ['signature', '', 'Must be required by a link'],
            'BIND_VOICE_INTERACTION': ['signature', '',
                                       'Must be required by a VoiceInteractionService, to ensure that only the system can bind to it.'],
            'BIND_VPN_SERVICE': ['signature', '',
                                 'Must be required by a VpnService, to ensure that only the system can bind to it.'],
            'BIND_VR_LISTENER_SERVICE': ['signature', '',
                                         'Must be required by an VrListenerService, to ensure that only the system can bind to it.'],
            'BLUETOOTH_PRIVILEGED': ['signature', '',
                                     'Allows applications to pair bluetooth devices without user interaction, and to allow or disallow phonebook access or message access. This is not available to third party applications.'],
            'BODY_SENSORS': ['dangerous', '',
                             'Allows an application to access data from sensors that the user uses to measure what is happening inside his/her body, such as heart rate.'],
            'CAPTURE_AUDIO_OUTPUT': ['signature', '', 'Allows an application to capture audio output.'],
            'CAPTURE_SECURE_VIDEO_OUTPUT': ['signature', '', 'Allows an application to capture secure video output.'],
            'CAPTURE_VIDEO_OUTPUT': ['signature', '', 'Allows an application to capture video output.'],
            'FOREGROUND_SERVICE': ['normal', '', 'Allows a regular application to use Service.startForeground'],
            'GET_ACCOUNTS_PRIVILEGED': ['signature', '', 'Allows access to the list of accounts in the Accounts Service.'],
            'INSTALL_SHORTCUT': ['normal', '', 'Allows an application to install a shortcut in Launcher.'],
            'INSTANT_APP_FOREGROUND_SERVICE': ['signature', '', 'Allows an instant app to create foreground services.'],

            'LOCATION_HARDWARE': ['signature', '',
                                  'Allows an application to use location features in hardware, such as the geofencing api.'],

            'READ_CELL_BROADCASTS': ['dangerous', '',
                                  'Allows an application to use location features in hardware, such as the geofencing api.'],

            'MANAGE_DOCUMENTS': ['signature', '',
                                 'Allows an application to manage access to documents, usually as part of a document picker.'],
            'MANAGE_OWN_CALLS': ['normal', '',
                                 'Allows a calling application which manages it own calls through the self-managed'],
            'MEDIA_CONTENT_CONTROL': ['signature', '',
                                      'Allows an application to know what content is playing and control its playback.'],
            'NFC_TRANSACTION_EVENT': ['normal', '', 'Allows applications to receive NFC transaction events.'],
            'READ_CALL_LOG': ['dangerous', '', 'Allows an application to read the user\'s call log.'],
            'READ_PHONE_NUMBERS': ['dangerous', '',
                                   'Allows read access to the device\'s phone number(s). This is a subset of the capabilities granted by'],
            'READ_VOICEMAIL': ['signature', '', 'Allows an application to read voicemails in the system.'],
            'REQUEST_COMPANION_RUN_IN_BACKGROUND': ['normal', '', 'Allows a companion app to run in the background.'],
            'REQUEST_COMPANION_USE_DATA_IN_BACKGROUND': ['normal', '',
                                                         'Allows a companion app to use data in the background.'],
            'REQUEST_DELETE_PACKAGES': ['normal', '',
                                        'Allows an application to request deleting packages. Apps targeting APIs'],
            'REQUEST_IGNORE_BATTERY_OPTIMIZATIONS': ['normal', '',
                                                     'Permission an application must hold in order to use'],
            'SEND_RESPOND_VIA_MESSAGE': ['signature', '',
                                         'Allows an application (Phone) to send a request to other applications to handle the respond-via-message action during incoming calls.'],
            'TRANSMIT_IR': ['normal', '', 'Allows using the device\'s IR transmitter, if available.'],
            'UNINSTALL_SHORTCUT': ['normal', '',
                                   'Don\'t use this permission in your app. This permission is no longer supported.'],
            'USE_BIOMETRIC': ['normal', '', 'Allows an app to use device supported biometric modalities.'],
            'USE_FINGERPRINT': ['normal', 'allow use of fingerprint',
                                'This constant was deprecated in API level 28. Applications should request USE_BIOMETRIC instead'],
            'WRITE_CALL_LOG': ['dangerous', '',
                               'Allows an application to write (but not read) the user\'s call log data.'],
            'WRITE_VOICEMAIL': ['signature', '',
                                'Allows an application to modify and remove existing voicemails in the system.'],
            'ACCESS_BACKGROUND_LOCATION': ['dangerous', 'access location in background',
                                           'Allows an app to access location in the background. If you\'re requesting this permission, you must also request either'],
            'ACCESS_MEDIA_LOCATION': ['dangerous', 'access any geographic locations',
                                      'Allows an application to access any geographic locations persisted in the user\'s shared collection.'],
            'ACTIVITY_RECOGNITION': ['dangerous', 'allow application to recognize physical activity',
                                     'Allows an application to recognize physical activity.'],
            'BIND_CALL_REDIRECTION_SERVICE': ['signature', '',
                                              'Must be required by a CallRedirectionService, to ensure that only the system can bind to it.'],
            'BIND_CARRIER_MESSAGING_CLIENT_SERVICE': ['signature', '',
                                                      'A subclass of CarrierMessagingClientService must be protected with this permission.'],
            'CALL_COMPANION_APP': ['normal', '',
                                   'Allows an app which implements the InCallService API to be eligible to be enabled as a calling companion app. This means that the Telecom framework will bind to the app\'s InCallService implementation when there are calls active. The app can use the InCallService API to view information about calls on the system and control these calls.'],
            'REQUEST_PASSWORD_COMPLEXITY': ['normal', '',
                                            'Allows an application to request the screen lock complexity and prompt users to update the screen lock to a certain complexity level.'],
            'SMS_FINANCIAL_TRANSACTIONS': ['signature', 'Allows financial apps to read filtered sms messages',
                                           'Allows financial apps to read filtered sms messages. Protection level: signature|appop'],
            'START_VIEW_PERMISSION_USAGE': ['signature', '',
                                            'Allows the holder to start the permission usage screen for an app.'],
            'USE_FULL_SCREEN_INTENT': ['normal', '',
                                       'Required for apps targeting Build.VERSION_CODES.Q that want to use notification full screen intents.'],
            'ACCESS_CALL_AUDIO': ['signature', 'Application can access call audio',
                                  'Allows an application assigned to the Dialer role to be granted access to the telephony call audio streams, both TX and RX.'],
            'BIND_CONTROLS': ['signature', 'Allows SystemUI to request third party controls.',
                              'Allows SystemUI to request third party controls. Should only be requested by the System and required by ControlsProviderService declarations.'],
            'BIND_QUICK_ACCESS_WALLET_SERVICE': ['signature', '',
                                                 'Must be required by a QuickAccessWalletService to ensure that only the system can bind to it.'],
            'INTERACT_ACROSS_PROFILES': ['signature', '', 'Allows interaction across profiles in the same profile group.'],
            'LOADER_USAGE_STATS': ['signature', '',
                                   'Allows a data loader to read a package\'s access logs. The access logs contain the set of pages referenced over time.'],
            'MANAGE_EXTERNAL_STORAGE': ['signature',
                                        'Allows an application a broad access to external storage in scoped storage',
                                        'Allows an application a broad access to external storage in scoped storage. Intended to be used by few apps that need to manage files on behalf of the users.'],
            'NFC_PREFERRED_PAYMENT_INFO': ['normal', '',
                                           'Allows applications to receive NFC preferred payment service information.'],
            'QUERY_ALL_PACKAGES': ['normal', '',
                                   'Allows query of any normal app on the device, regardless of manifest declarations.'],
            'READ_PRECISE_PHONE_STATE': ['signature', '',
                                         'Allows read only access to precise phone state. Allows reading of detailed information about phone state for special-use applications such as dialers, carrier applications, or ims applications.'],
            'HAND_TRACKING': ['dangerous', '',
                                   'Allows an app to use hand tracking component.'],    #oculus permission actually normal
            'RENDER_MODEL': ['dangerous', '',
                              'Allows an app to use model rendering component.'],   #oculus permission
            'TRACKED_KEYBOARD': ['normal', '',
                              'Allows an app to use keyboard tracking component.'], #oculus permission
            'USE_ANCHOR_API': ['normal', '',
                              'Allows an app to use anchor.'],  #oculus下的权限类型
            'FACE_TRACKING': ['dangerous', '',
                              'Allows an app to use face tracking component.'],     #oculus permission
            'TOUCH_CONTROLLER_PRO': ['dangerous', '',
                              'Allows an app to use touch controller component.'],      #oculus permission
            'BODY_TRACKING': ['dangerous', '',
                              'Allows an app to use body tracking component.'],     #oculus permission
            'EYE_TRACKING': ['dangerous', '',
                              'Allows an app to use eye tracking component.'],      #oculus permission
            'DEVICE_CONFIG_PUSH_TO_CLIENT': ['signature', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission
            'ACCESS_MR_SENSOR_DATA': ['dangerous', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission
            'CODEC_AVATAR': ['dangerous', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission
            'CODEC_AVATAR_CAMERA': ['dangerous', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission
            'FACE_EYE_INTERNAL_API': ['dangerous', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission
            'FITNESS_TOOLKIT': ['dangerous', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission
            'ORTHOFIT_DATA': ['dangerous', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission
            'RECORD_MR_STREAM': ['dangerous', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission
            'TRACKING_INJECTION': ['dangerous', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission
            'USE_SCENE': ['dangerous', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission
            'READ_TV_LISTINGS': ['dangerous', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission
            'HANDTRACKING_DATA': ['dangerous', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission
            
            
            
            
            
            
            
            
            
            
            
            
            
            'ACCESS_WIMAX_STATE': ['normal', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission
            'CHANGE_WIMAX_STATE': ['normal', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission
            'READ_INSTALL_SESSIONS': ['normal', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission
            'FBCONNECT_CONTENT_PROVIDER_READ_ACCESS': ['normal', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission       
            'FBCONNECT_CONTENT_PROVIDER_WRITE_ACCESS': ['signatureOrSystem', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission    
                              
                              
                              
            'ACCESS_ALL_DOWNLOADS': ['signature', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission    
            'ACCESS_BROADCAST_RADIO': ['signature', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission    
            'ACCESS_BLUETOOTH_SHARE': ['signature', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission   
            'REQUEST_DEVELOPER_STATUS': ['signatureOrSystem', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission    
            'PLATFORM_ATTESTATION': ['signature', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission     
                              
                              
                              
                              
                                                                     
            'READ_PACKAGE_INTEGRITY_PROVIDER': ['signature', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission     
            'BROADCAST_PERMISSION': ['signatureOrSystem', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission                                            
            'READ_FITNESS_DATA': ['signature', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission                                           
            'WRITE_FITNESS_DATA': ['signatureOrSystem', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission                                            
            'OVR_PLATFORM_BROADCAST': ['signature', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission      
                              
                              
                              
                              
            'ALWAYS_CAPTURE_MIC_AUDIO_INPUT': ['signature', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission      
            'DUMP_ON_DEMAND': ['signature', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission      
            'INTERACT_ACROSS_USERS': ['signature', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission      
            'PLAY_AUDIO_BACKGROUND': ['normal', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission      
            'PRIORITY_CAPTURE_MIC_AUDIO_INPUT': ['signature', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission      
            'QUIET_FOREGROUND_SERVICE': ['signature', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission
                              
                              
                              
                              
            'READ_SETTINGS': ['signature', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission 
            'READ_PRIVILEGED_PHONE_STATE': ['signature', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission
            'MANAGE_USERS': ['signatureOrSystem', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission
            'INTERACT_ACROSS_USERS_FULL': ['signature', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission
            'CONNECT_TO_DUMPSYSPROXY': ['signature', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission
            'RECORD_AUDIO_BACKGROUND': ['signature', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission
                              
                              
                              
            'UPDATE_TELEMETRY_SESSIONS': ['signature', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission 
            'ACCESS_BACKGROUND_INPUT_TRACKING': ['signature', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission
            'READ_CONTROLLER_STATUS': ['signature', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission
            'WRITE_MEDIA_STORAGE': ['signature', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission
            'MODIFY_CONTROLLER_STATUS': ['signature', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission
            'READ_DEVICE_CONFIG': ['signature', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission
            'METADEVICECONFIG_RECEIVE_FROM_SERVICE_DEBUG': ['signature', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission 
            'METADEVICECONFIG_RECEIVE_FROM_SERVICE': ['signature', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission                                                                    
            'ACCESS_PANEL_ACTIVITY_FEATURES': ['signature', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission
            'READ_FOCUS_STATE': ['signature', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission
            'POST_NOTIFICATIONS': ['signature', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission  
            'BIND_PRESENCE_SERVICE': ['signature', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission
            'MANAGE_LOCKSCREEN': ['signature', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission
            'METACAM_SCREEN_CAPTURE': ['signature', '',
                              'Allows an app to send device configuration to client.'],      #oculus permission       
                                                                                                                               
                               
        },

        'MANIFEST_PERMISSION_GROUP':
            {

                'ACCOUNTS': 'Permissions for direct access to the accounts managed by the Account Manager.',
                'COST_MONEY': 'Used for permissions that can be used to make the user spend money without their direct involvement.',
                'DEVELOPMENT_TOOLS': 'Group of permissions that are related to development features.',
                'HARDWARE_CONTROLS': 'Used for permissions that provide direct access to the hardware on the device.',
                'LOCATION': 'Used for permissions that allow access to the user\'s current location.',
                'MESSAGES': 'Used for permissions that allow an application to send messages on behalf of the user or intercept messages being received by the user.',
                'NETWORK': 'Used for permissions that provide access to networking services.',
                'PERSONAL_INFO': 'Used for permissions that provide access to the user\'s private data, such as contacts, calendar events, e-mail messages, etc.',
                'PHONE_CALLS': 'Used for permissions that are associated with accessing and modifyign telephony state: intercepting outgoing calls, reading and modifying the phone state.',
                'STORAGE': 'Group of permissions that are related to SD card access.',
                'SYSTEM_TOOLS': 'Group of permissions that are related to system APIs.',
            },
    }

def extract_version_number(folder_name):
    """Extract version number from folder name"""
    match = re.search(r'q1_v(\d+)', folder_name)
    if match:
        return int(match.group(1))
    return None

def display_permission_stats_per_app(version_results):
    """Compute and display mean and median permissions per app for each version"""
    from statistics import mean, median

    print("\nPERMISSION STATS PER APP (Mean and Median per Version):")
    print("=" * 60)

    for version in sorted(version_results.keys()):
        result = version_results[version]
        apps_data = result["apps"]
        summary = result["directory_summary"]
        apps = summary["successful_analyses"]
        if apps == 0:
            continue

        # Collect per-app permission counts by type
        permission_counts = {
            "dangerous": [],
            "normal": [],
            "signature": [],
            "signatureOrSystem": [],
            "others": []
        }

        for app_data in apps_data.values():
            if "permissions" in app_data:
                for ptype in permission_counts:
                    permission_counts[ptype].append(len(app_data["permissions"].get(ptype, [])))

        print(f"\nVersion v{version} (Apps analyzed: {apps}):")
        for ptype, counts in permission_counts.items():
            mean_val = mean(counts) if counts else 0
            median_val = median(counts) if counts else 0
            print(f"  {ptype.title():<20}: Mean = {mean_val:.2f}, Median = {median_val:.2f}")


def analyze_versions(base_path="."):
    # Get firmware version folders
    items = os.listdir(base_path)
    version_folders = [item for item in items 
                      if item.startswith('q1_v') and os.path.isdir(os.path.join(base_path, item))]
    
    version_results = defaultdict(dict)
    
    # Sort folders by version number
    version_folders.sort(key=extract_version_number)
    
    print(f"Found {len(version_folders)} firmware versions to analyze")
    
    # Analyze each version
    for folder in version_folders:
        version_num = extract_version_number(folder)
        if version_num is not None:
            print(f"\nAnalyzing firmware version {version_num}...")
            apps_path = os.path.join(base_path, folder, "apps")
            if os.path.exists(apps_path):
                # Create a fresh analyzer for each version to avoid accumulation
                analyzer = PermissionAnalyzer()
                results = analyzer.analyze_directory(apps_path)
                version_results[version_num] = results
            else:
                print(f"Warning: No apps directory found for version {version_num}")
    
    # Create visualization
    plot_permissions_trend(version_results)
    display_overall_statistics(version_results)
    display_permission_stats_per_app(version_results)

def get_permission_counts(apps_data):
    """Get total counts for each permission type"""
    counts = {
        "dangerous": 0,
        "normal": 0,
        "signature": 0,
        "signatureOrSystem": 0,
        "others": 0
    }
    
    for app_data in apps_data.values():
        if "permissions" in app_data:
            for perm_type, perms in app_data["permissions"].items():
                counts[perm_type] += len(perms)
    
    return counts

def get_permission_details(apps_data):
    """Get detailed permission usage by type"""
    details = {
        "dangerous": Counter(),
        "normal": Counter(),
        "signature": Counter(),
        "signatureOrSystem": Counter(),
        "others": Counter()
    }
    
    for app_data in apps_data.values():
        if "permissions" in app_data:
            for perm_type, perms in app_data["permissions"].items():
                details[perm_type].update(perms)
    
    return details

def display_overall_statistics(version_results):
    """Compute and display mean number of each permission type across versions"""
    total = {
        "dangerous": 0,
        "normal": 0,
        "signature": 0,
        "signatureOrSystem": 0,
        "others": 0
    }
    version_count = 0

    for version, result in version_results.items():
        summary = result.get("directory_summary")
        if summary and summary.get("successful_analyses", 0) > 0:
            counts = get_permission_counts(result["apps"])
            for key in total:
                total[key] += counts[key]
            version_count += 1

    if version_count == 0:
        print("No successful versions to compute statistics.")
        return

    print("\nOVERALL PERMISSION STATISTICS (Mean per Version):")
    print("=" * 50)
    for key in total:
        print(f"{key.title()} permissions: {total[key] / version_count:.2f} per version")


def plot_permissions_trend(version_results):
    """Plot permissions trend across versions (only stacked bar and app count)"""
    if not version_results:
        print("No data to plot!")
        return

    versions = sorted(version_results.keys())

    # Initialize arrays for each permission type
    dangerous_perms = []
    normal_perms = []
    signature_perms = []
    signature_system_perms = []
    other_perms = []
    apps_count = []

    # Collect data for each version
    for version in versions:
        summary = version_results[version]["directory_summary"]
        successful_analyses = summary["successful_analyses"]
        apps_count.append(successful_analyses)

        # Get permission counts
        perm_summary = get_permission_counts(version_results[version]["apps"])
        dangerous_perms.append(perm_summary["dangerous"])
        normal_perms.append(perm_summary["normal"])
        signature_perms.append(perm_summary["signature"])
        signature_system_perms.append(perm_summary["signatureOrSystem"])
        other_perms.append(perm_summary["others"])

    # Create figure with 2 subplots now (only Plot 2 and 3)
    fig, axes = plt.subplots(2, 1, figsize=(15, 12))

    # Plot 2: Permission type distribution (stacked bar chart)
    bottom = np.zeros(len(versions))
    width = 0.8

    for data, label, color in [
        (dangerous_perms, 'Dangerous', 'r'),
        (normal_perms, 'Normal', 'g'),
        (signature_perms, 'Signature', 'b'),
        (signature_system_perms, 'SignatureOrSystem', 'm'),
        (other_perms, 'Others', 'y')
    ]:
        axes[0].bar(versions, data, width, bottom=bottom, label=label, color=color, alpha=0.7)
        bottom += np.array(data)

    axes[0].set_title('Permission Type Distribution')
    axes[0].set_xlabel('Version Number')
    axes[0].set_ylabel('Number of Permissions')
    axes[0].legend()
    axes[0].set_xticks(versions)
    axes[0].set_xticklabels([f'v{v}' for v in versions], rotation=45)

    # Plot 3: Number of apps analyzed
    axes[1].bar(versions, apps_count, color='g', alpha=0.6)
    axes[1].set_title('Number of Apps Analyzed per Version')
    axes[1].set_xlabel('Version Number')
    axes[1].set_ylabel('Number of Apps')
    axes[1].grid(True, alpha=0.3)
    axes[1].set_xticks(versions)
    axes[1].set_xticklabels([f'v{v}' for v in versions], rotation=45)

    plt.tight_layout()
    plt.savefig('firmware_permissions_trend.png')
    plt.close()

    print("\nSaved stacked bar chart and app count as 'firmware_permissions_trend.png'")

    
    print("\nPermissions trend visualization saved as 'firmware_permissions_trend.png'")
    
    # Print summary statistics
    print("\nSUMMARY STATISTICS:")
    print("=" * 50)
    for version in versions:
        summary = version_results[version]["directory_summary"]
        apps = summary["successful_analyses"]
        perm_summary = get_permission_counts(version_results[version]["apps"])
        
        print(f"\nVersion {version}:")
        print(f"  Apps analyzed: {apps}")
        print(f"  Permission counts:")
        print(f"    Dangerous: {perm_summary['dangerous']}")
        print(f"    Normal: {perm_summary['normal']}")
        print(f"    Signature: {perm_summary['signature']}")
        print(f"    SignatureOrSystem: {perm_summary['signatureOrSystem']}")
        print(f"    Others: {perm_summary['others']}")
        
        print("  Most common permissions by type:")
        perm_details = get_permission_details(version_results[version]["apps"])
        for perm_type in ['dangerous', 'normal', 'signature', 'signatureOrSystem']:
            if perm_details[perm_type]:
                print(f"\n    {perm_type.upper()} permissions:")
                for perm, count in sorted(perm_details[perm_type].items(), key=lambda x: x[1], reverse=True)[:5]:
                    print(f"      - {perm}: {count} apps ({(count/apps)*100:.1f}% of apps)")
        
        # Add after the existing for loop for permission types
        print("\n    OTHER permissions (top 20):")
        if perm_details["others"]:
            # Sort by count and get top 20
            top_others = sorted(perm_details["others"].items(), key=lambda x: x[1], reverse=True)[:20]
            for perm, count in top_others:
                print(f"      - {perm}: {count} apps ({(count/apps)*100:.1f}% of apps)")
        else:
            print("      No other permissions found")

if __name__ == "__main__":
    analyze_versions()
