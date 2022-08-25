use core::fmt;
use core::panic::{RefUnwindSafe, UnwindSafe};

use super::{NSArray, NSDictionary, NSObject, NSString, NSUInteger};
use crate::rc::{Id, Shared};
use crate::{
    extern_class, extern_methods, msg_send, msg_send_bool, msg_send_id, ns_string, ClassType,
    Encode, Encoding, RefEncode,
};

extern_class!(
    /// A collection of information about the current process.
    ///
    /// See [Apple's documentation](https://developer.apple.com/documentation/foundation/nsprocessinfo?language=objc).
    #[derive(PartialEq, Eq, Hash)]
    pub struct NSProcessInfo;

    unsafe impl ClassType for NSProcessInfo {
        type Super = NSObject;
    }
);

// SAFETY: The documentation explicitly states:
// > NSProcessInfo is thread-safe in macOS 10.7 and later.
unsafe impl Send for NSProcessInfo {}
unsafe impl Sync for NSProcessInfo {}

impl UnwindSafe for NSProcessInfo {}
impl RefUnwindSafe for NSProcessInfo {}

extern_methods!(
    unsafe impl NSProcessInfo {
        /// Returns the shared [`NSProcessInfo`] object for the current process.
        ///
        /// # Examples
        ///
        /// ```
        /// use objc2::foundation::NSProcessInfo;
        /// # #[cfg(feature = "gnustep-1-7")]
        /// # unsafe { objc2::__gnustep_hack::get_class_to_force_linkage() };
        ///
        /// let process_info = NSProcessInfo::process_info();
        /// println!("{:?}", process_info);
        /// ```
        pub fn process_info() -> Id<NSProcessInfo, Shared> {
            unsafe { msg_send_id![Self::class(), processInfo] }
        }

        /// Returns an array of the arguments used to start the current process.
        ///
        /// # Examples
        ///
        /// ```
        /// use objc2::foundation::NSProcessInfo;
        /// # #[cfg(feature = "gnustep-1-7")]
        /// # unsafe { objc2::__gnustep_hack::get_class_to_force_linkage() };
        ///
        /// let process_info = NSProcessInfo::process_info();
        /// for arg in process_info.arguments().iter() {
        ///     println!("{}", arg);
        /// }
        /// ```
        pub fn arguments(&self) -> Id<NSArray<NSString, Shared>, Shared> {
            unsafe { msg_send_id![self, arguments] }
        }

        /// Returns a dictionary of the environment variables provided to the
        /// current process.
        ///
        /// # Examples
        ///
        /// ```
        /// use core::iter::zip;
        /// use objc2::foundation::NSProcessInfo;
        /// # #[cfg(feature = "gnustep-1-7")]
        /// # unsafe { objc2::__gnustep_hack::get_class_to_force_linkage() };
        ///
        /// let process_info = NSProcessInfo::process_info();
        /// let environment = process_info.environment();
        /// for (env_var, val) in zip(environment.iter_keys(), environment.iter_values()) {
        ///     println!("{}: {}", env_var, val);
        /// }
        /// ```
        pub fn environment(&self) -> Id<NSDictionary<NSString, NSString>, Shared> {
            unsafe { msg_send_id![self, environment] }
        }

        /// Returns a globally unique identifier for the current process.
        ///
        /// # Examples
        ///
        /// ```
        /// use objc2::foundation::NSProcessInfo;
        /// # #[cfg(feature = "gnustep-1-7")]
        /// # unsafe { objc2::__gnustep_hack::get_class_to_force_linkage() };
        ///
        /// let process_info = NSProcessInfo::process_info();
        /// println!("{}", process_info.globally_unique_string());
        /// ```
        pub fn globally_unique_string(&self) -> Id<NSString, Shared> {
            unsafe { msg_send_id![self, globallyUniqueString] }
        }

        /// Returns the name of the machine on which the current process is
        /// running.
        ///
        /// # Examples
        ///
        /// ```
        /// use objc2::foundation::NSProcessInfo;
        /// # #[cfg(feature = "gnustep-1-7")]
        /// # unsafe { objc2::__gnustep_hack::get_class_to_force_linkage() };
        ///
        /// let process_info = NSProcessInfo::process_info();
        /// println!("Host name: {}", process_info.host_name());
        /// ```
        pub fn host_name(&self) -> Id<NSString, Shared> {
            unsafe { msg_send_id![self, hostName] }
        }

        /// Returns a number representing the operating system type.
        ///
        /// Available on GNUstep. Deprecated on iOS, iPadOS, macOS, tvOS, and watchOS.
        ///
        /// # Examples
        ///
        /// ```
        /// use objc2::foundation::NSProcessInfo;
        /// # #[cfg(feature = "gnustep-1-7")]
        /// # unsafe { objc2::__gnustep_hack::get_class_to_force_linkage() };
        ///
        /// let process_info = NSProcessInfo::process_info();
        /// println!("OS: {}", process_info.operating_system());
        /// ```
        #[cfg(feature = "gnustep-1-7")]
        #[sel(operatingSystem)]
        pub fn operating_system(&self) -> NSUInteger;

        /// Returns a string representing the operating system type.
        ///
        /// Available on GNUstep. Deprecated on iOS, iPadOS, macOS, tvOS, and watchOS.
        ///
        /// # Examples
        ///
        /// ```
        /// use objc2::foundation::NSProcessInfo;
        /// # #[cfg(feature = "gnustep-1-7")]
        /// # unsafe { objc2::__gnustep_hack::get_class_to_force_linkage() };
        ///
        /// let process_info = NSProcessInfo::process_info();
        /// println!("OS name: {}", process_info.operating_system_name());
        /// ```
        #[cfg(feature = "gnustep-1-7")]
        pub fn operating_sytem_name(&self) -> Id<NSString, Shared> {
            msg_send_id![self, operatingSystemName]
        }

        /// Returns the operating system's version.
        ///
        /// Available on iOS 8.0+ and macOS 10.10+.
        ///
        /// # Examples
        ///
        /// ```
        /// use objc2::foundation::{NSOperatingSystemVersion, NSProcessInfo};
        /// # #[cfg(feature = "gnustep-1-7")]
        /// # unsafe { objc2::__gnustep_hack::get_class_to_force_linkage() };
        ///
        /// let process_info = NSProcessInfo::process_info();
        /// let os_version = process_info.operating_system_version();
        /// println!(
        ///     "OS Version: {}.{}.{}",
        ///     os_version.major_version, os_version.minor_version, os_version.patch_version
        /// );
        /// ```
        #[cfg(all(feature = "apple", not(macos_10_7)))]
        #[sel(operatingSystemVersion)]
        pub fn operating_system_version(&self) -> NSOperatingSystemVersion;

        /// Returns whether the version of the operating system for the current
        /// process is the same or later than the given version.
        ///
        /// Available on iOS 8.0+ and macOS 10.10+.
        ///
        /// # Examples
        ///
        /// use objc2::foundation::{NSOperatingSystemVersion, NSProcessInfo};
        /// # #[cfg(feature = "gnustep-1-7")]
        /// # unsafe { objc2::__gnustep_hack::get_class_to_force_linkage() };
        ///
        /// let process_info = NSProcessInfo::process_info();
        /// let version = NSOperatingSystemVersion {
        ///     major_version: 10,
        ///     minor_version: 7,
        ///     patch_version: 0
        /// };
        /// println!("Is at least 10.7? {}", process_info.is_operating_system_at_least_version(version));
        /// ```
        #[cfg(all(feature = "apple", not(macos_10_7)))]
        pub fn is_operating_system_at_least_version(
            &self,
            version: NSOperatingSystemVersion,
        ) -> bool {
            unsafe { msg_send_bool![self, isOperatingSystemAtLeastVersion: version] }
        }

        /// Returns a string containing the operating system's version.
        ///
        /// # Examples
        ///
        /// ```
        /// use objc2::foundation::NSProcessInfo;
        /// # #[cfg(feature = "gnustep-1-7")]
        /// # unsafe { objc2::__gnustep_hack::get_class_to_force_linkage() };
        ///
        /// let process_info = NSProcessInfo::process_info();
        /// println!("OS version string: {}", process_info.operating_system_version_string());
        /// ```
        pub fn operating_system_version_string(&self) -> Id<NSString, Shared> {
            unsafe { msg_send_id![self, operatingSystemVersionString] }
        }

        /// The amount of physical memory on the machine in bytes.
        ///
        /// # Examples
        ///
        /// ```
        /// use objc2::foundation::NSProcessInfo;
        /// # #[cfg(feature = "gnustep-1-7")]
        /// # unsafe { objc2::__gnustep_hack::get_class_to_force_linkage() };
        ///
        /// let process_info = NSProcessInfo::process_info();
        /// println!("Physical memory: {}B", process_info.physical_memory());
        /// ```
        #[sel(physicalMemory)]
        pub fn physical_memory(&self) -> u64;

        /// Returns the process identifier (PID).
        ///
        /// # Examples
        ///
        /// ```
        /// use objc2::foundation::NSProcessInfo;
        /// # #[cfg(feature = "gnustep-1-7")]
        /// # unsafe { objc2::__gnustep_hack::get_class_to_force_linkage() };
        ///
        /// let process_info = NSProcessInfo::process_info();
        /// println!("PID: {}", process_info.process_identifier());
        /// ```
        #[sel(processIdentifier)]
        pub fn process_identifier(&self) -> i32;

        /// Returns the name of the current process.
        ///
        /// # Examples
        ///
        /// ```
        /// use objc2::foundation::NSProcessInfo;
        /// # #[cfg(feature = "gnustep-1-7")]
        /// # unsafe { objc2::__gnustep_hack::get_class_to_force_linkage() };
        ///
        /// let process_info = NSProcessInfo::process_info();
        /// println!("Process name: {}", process_info.process_name());
        /// ```
        pub fn process_name(&self) -> Id<NSString, Shared> {
            unsafe { msg_send_id![self, processName] }
        }

        /// Sets the name of the current process.
        ///
        /// # Examples
        ///
        /// ```
        /// use objc2::ns_string;
        /// use objc2::foundation::NSProcessInfo;
        /// # #[cfg(feature = "gnustep-1-7")]
        /// # unsafe { objc2::__gnustep_hack::get_class_to_force_linkage() };
        ///
        /// let process_info = NSProcessInfo::process_info();
        /// let original_name = process_info.process_name();
        /// process_info.set_process_name(ns_string!("objc2-process-info"));
        /// println!("Process name: {}", process_info.process_name());
        /// process_info.set_process_name(&original_name);
        /// ```
        #[cfg(feature = "gnustep-1-7")]
        #[sel(setProcessName:)]
        pub fn set_process_name(&self, process_name: &NSString);

        /// Sets the name of the current process.
        ///
        /// # Examples
        ///
        /// ```
        /// use objc2::ns_string;
        /// use objc2::foundation::NSProcessInfo;
        /// # #[cfg(feature = "gnustep-1-7")]
        /// # unsafe { objc2::__gnustep_hack::get_class_to_force_linkage() };
        ///
        /// let process_info = NSProcessInfo::process_info();
        /// let original_name = process_info.process_name();
        /// process_info.set_process_name(ns_string!("objc2-process-info"));
        /// println!("Process name: {}", process_info.process_name());
        /// process_info.set_process_name(&original_name);
        /// ```
        #[cfg(feature = "apple")]
        pub fn set_process_name(&self, process_name: &NSString) {
            unsafe {
                msg_send![
                    self,
                    setValue: process_name,
                    forKey: ns_string!("processName")
                ]
            }
        }

        /// Returns the number of processing cores on the machine.
        ///
        /// # Examples
        ///
        /// ```
        /// use objc2::foundation::NSProcessInfo;
        /// # #[cfg(feature = "gnustep-1-7")]
        /// # unsafe { objc2::__gnustep_hack::get_class_to_force_linkage() };
        ///
        /// let process_info = NSProcessInfo::process_info();
        /// println!("Processor count: {}", process_info.processor_count());
        /// ```
        #[sel(processorCount)]
        pub fn processor_count(&self) -> NSUInteger;

        /// Returns the number of active processing cores on the machine.
        ///
        /// # Examples
        ///
        /// ```
        /// use objc2::foundation::NSProcessInfo;
        /// # #[cfg(feature = "gnustep-1-7")]
        /// # unsafe { objc2::__gnustep_hack::get_class_to_force_linkage() };
        ///
        /// let process_info = NSProcessInfo::process_info();
        /// println!("Active processor count: {}", process_info.active_processor_count());
        /// ```
        #[sel(activeProcessorCount)]
        pub fn active_processor_count(&self) -> NSUInteger;

        /// Returns the amount of time the system has been running since it was
        /// last restarted.
        ///
        /// # Examples
        ///
        /// ```
        /// use objc2::foundation::NSProcessInfo;
        /// # #[cfg(feature = "gnustep-1-7")]
        /// # unsafe { objc2::__gnustep_hack::get_class_to_force_linkage() };
        ///
        /// let process_info = NSProcessInfo::process_info();
        /// println!("System uptime: {}", process_info.system_uptime());
        /// ```
        #[cfg(feature = "gnustep-1-7")]
        #[sel(systemUptime)]
        pub fn system_uptime(&self) -> NSUInteger;

        /// Returns the amount of time the system has been running since it was
        /// last restarted.
        ///
        /// # Examples
        ///
        /// ```
        /// use objc2::foundation::NSProcessInfo;
        /// # #[cfg(feature = "gnustep-1-7")]
        /// # unsafe { objc2::__gnustep_hack::get_class_to_force_linkage() };
        ///
        /// let process_info = NSProcessInfo::process_info();
        /// println!("System uptime: {}", process_info.system_uptime());
        /// ```
        #[cfg(feature = "apple")]
        #[sel(systemUptime)]
        pub fn system_uptime(&self) -> f64;

        /// Returns the current thermal state of the machine.
        ///
        /// Available on iOS 11.0+ and macOS 10.10.3+.
        ///
        /// # Examples
        ///
        /// ```
        /// use objc2::foundation::{NSProcessInfo, NSProcessInfoThermalState};
        /// # #[cfg(feature = "gnustep-1-7")]
        /// # unsafe { objc2::__gnustep_hack::get_class_to_force_linkage() };
        ///
        /// let process_info = NSProcessInfo::process_info();
        /// println!("{:?}", process_info.thermal_state());
        /// ```
        #[cfg(all(feature = "apple", not(macos_10_7)))]
        #[sel(thermalState)]
        pub fn thermal_state(&self) -> NSProcessInfoThermalState;

        /// Returns the name of the current user.
        ///
        /// Available on macOS 10.12+.
        ///
        /// # Examples
        ///
        /// ```
        /// use objc2::foundation::NSProcessInfo;
        /// # #[cfg(feature = "gnustep-1-7")]
        /// # unsafe { objc2::__gnustep_hack::get_class_to_force_linkage() };
        ///
        /// let process_info = NSProcessInfo::process_info();
        /// println!("User name: {}", process_info.user_name());
        /// ```
        #[cfg(all(feature = "apple", target_os = "macos", not(macos_10_7)))]
        pub fn user_name(&self) -> Id<NSString, Shared> {
            unsafe { msg_send_id![self, userName] }
        }

        /// Returns the full name of the current user.
        ///
        /// Only available in macOS 10.12+.
        ///
        /// # Examples
        ///
        /// ```
        /// use objc2::foundation::NSProcessInfo ;
        /// # #[cfg(feature = "gnustep-1-7")]
        /// # unsafe { objc2::__gnustep_hack::get_class_to_force_linkage() };
        ///
        /// let process_info = NSProcessInfo::process_info();
        /// println!("Full user name: {}", process_info.full_user_name());
        /// ```
        #[cfg(all(feature = "apple", target_os = "macos", not(macos_10_7)))]
        pub fn full_user_name(&self) -> Id<NSString, Shared> {
            unsafe { msg_send_id![self, fullUserName] }
        }

        /// Enables the application for quick killing using sudden termination.
        ///
        /// Available on macOS 10.6+.
        ///
        /// # Examples
        ///
        /// ```
        /// use objc2::foundation::NSProcessInfo;
        /// # #[cfg(feature = "gnustep-1-7")]
        /// # unsafe { objc2::__gnustep_hack::get_class_to_force_linkage() };
        ///
        /// let process_info = NSProcessInfo::process_info();
        /// process_info.enable_sudden_termination();
        /// ```
        #[cfg(all(feature = "apple", target_os = "macos"))]
        #[sel(enableSuddenTermination)]
        pub fn enable_sudden_termination(&self);

        /// Disables the application for quick killing using sudden termination.
        ///
        /// Available on macOS 10.6+.
        ///
        /// # Examples
        ///
        /// ```
        /// use objc2::foundation::NSProcessInfo;
        /// # #[cfg(feature = "gnustep-1-7")]
        /// # unsafe { objc2::__gnustep_hack::get_class_to_force_linkage() };
        ///
        /// let process_info = NSProcessInfo::process_info();
        /// process_info.disable_sudden_termination();
        /// ```
        #[cfg(all(feature = "apple", target_os = "macos"))]
        #[sel(disableSuddenTermination)]
        pub fn disable_sudden_termination(&self);

        /// Enables automatic termination for the application.
        ///
        /// Available on macOS 10.7+.
        ///
        /// # Examples
        ///
        /// ```
        /// use objc2::ns_string;
        /// use objc2::foundation::NSProcessInfo;
        /// # #[cfg(feature = "gnustep-1-7")]
        /// # unsafe { objc2::__gnustep_hack::get_class_to_force_linkage() };
        ///
        /// let process_info = NSProcessInfo::process_info();
        /// process_info.enable_automatic_termination(ns_string!("reason"));
        /// ```
        #[cfg(all(feature = "apple", target_os = "macos"))]
        #[sel(enableAutomaticTermination:)]
        pub fn enable_automatic_termination(&self, reason: &NSString);

        /// Disables automatic termination for the application.
        ///
        /// Available on macOS 10.7+.
        ///
        /// # Examples
        ///
        /// ```
        /// use objc2::ns_string;
        /// use objc2::foundation::NSProcessInfo;
        /// # #[cfg(feature = "gnustep-1-7")]
        /// # unsafe { objc2::__gnustep_hack::get_class_to_force_linkage() };
        ///
        /// let process_info = NSProcessInfo::process_info();
        /// process_info.disable_automatic_termination(ns_string!("reason"));
        /// ```
        #[cfg(all(feature = "apple", target_os = "macos"))]
        #[sel(disableAutomaticTermination:)]
        pub fn disable_automatic_termination(&self, reason: &NSString);

        /// Returns whether or not the current process supports automatic
        /// termination.
        ///
        /// Available on macOS 10.7+.
        ///
        /// # Examples
        ///
        /// ```
        /// use objc2::foundation::NSProcessInfo;
        /// # #[cfg(feature = "gnustep-1-7")]
        /// # unsafe { objc2::__gnustep_hack::get_class_to_force_linkage() };
        ///
        /// let process_info = NSProcessInfo::process_info();
        /// println!("Auto termination support enabled: {}", process_info.automatic_termination_support_enabled());
        /// ```
        #[cfg(all(feature = "apple", target_os = "macos"))]
        pub fn automatic_termination_support_enabled(&self) -> bool {
            unsafe { msg_send_bool![self, automaticTerminationSupportEnabled] }
        }

        // The two methods below are only available on macOS 10.15 and newer

        // #[cfg(feature = "apple")]
        // pub fn mac_catalyst_app(&self) -> bool {
        // unsafe { msg_send_bool![self, macCatalystApp] }
        // }

        // #[cfg(feature = "apple")]
        // pub fn is_ios_app_on_mac(&self) -> bool {
        // unsafe { msg_send_bool![self, iOSAppOnMac] }
        // }
    }
);

impl fmt::Debug for NSProcessInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NSProcessInfo")
            .field("process_name", &self.process_name())
            .field("host_name", &self.host_name())
            .field(
                "operating_system_version_string",
                &self.operating_system_version_string(),
            )
            .field("physical_memory", &self.physical_memory())
            .field("process_identifier", &self.process_identifier())
            .field("processor_count", &self.processor_count())
            .finish_non_exhaustive()
    }
}

/// A structure containing the major, minor, and patch version numbers of the
/// operating system.
///
/// See [Apple's documentation](https://developer.apple.com/documentation/foundation/nsoperatingsystemversion?language=objc).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct NSOperatingSystemVersion {
    pub major_version: NSUInteger,
    pub minor_version: NSUInteger,
    pub patch_version: NSUInteger,
}

unsafe impl Encode for NSOperatingSystemVersion {
    const ENCODING: Encoding<'static> = Encoding::Struct(
        "NSOperatingSystemVersion",
        &[
            NSUInteger::ENCODING,
            NSUInteger::ENCODING,
            NSUInteger::ENCODING,
        ],
    );
}

unsafe impl RefEncode for NSOperatingSystemVersion {
    const ENCODING_REF: Encoding<'static> = Encoding::Pointer(&Self::ENCODING);
}

/// Values for the system's thermal state.
///
/// See [Apple's documentation](https://developer.apple.com/documentation/foundation/nsprocessinfothermalstate?language=objc).
#[repr(isize)] // NSInteger
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NSProcessInfoThermalState {
    Nominal = 0,
    Fair,
    Serious,
    Critical,
}

unsafe impl Encode for NSProcessInfoThermalState {
    const ENCODING: Encoding<'static> = Encoding::Int;
}

unsafe impl RefEncode for NSProcessInfoThermalState {
    const ENCODING_REF: Encoding<'static> = Encoding::Pointer(&Self::ENCODING);
}

impl Default for NSProcessInfoThermalState {
    #[inline]
    fn default() -> Self {
        Self::Nominal
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;

    use super::*;

    #[test]
    fn test_arguments() {
        let process_info = NSProcessInfo::process_info();
        let args = process_info.arguments();
        assert!(args.len() > 0);
    }

    #[test]
    fn test_environment() {
        let process_nfo = NSProcessInfo::process_info();
        let env_vars = process_nfo.environment();
        assert!(env_vars.len() > 0);
    }

    #[cfg(feature = "gnustep-1-7")]
    #[test]
    fn test_operating_system() {
        let process_info = NSProcessInfo::process_info();
        let operating_system = process_info.operating_system();
        assert!(operating_sytem > 0);
    }

    #[cfg(all(feature = "apple", not(macos_10_7)))]
    #[test]
    fn test_operating_system_version() {
        let process_info = NSProcessInfo::process_info();
        let operating_system_version = process_info.operating_system_version();
        assert!(operating_system_version.major_version > 0);
    }

    #[cfg(all(feature = "apple", not(macos_10_7)))]
    #[test]
    fn test_is_operating_system_at_least_version() {
        let process_info = NSProcessInfo::process_info();
        assert!(
            process_info.is_operating_system_at_least_version(NSOperatingSystemVersion::default())
        );
    }

    #[test]
    fn test_physical_memory() {
        let process_info = NSProcessInfo::process_info();
        let physical_memory = process_info.physical_memory();
        assert!(physical_memory > 0);
    }

    #[test]
    fn test_process_identifier() {
        let process_info = NSProcessInfo::process_info();
        let pid = process_info.process_identifier();
        assert!(pid > 0);
    }

    #[test]
    fn test_set_process_name() {
        let process_info = NSProcessInfo::process_info();
        let new_name = ns_string!("objc2-process-info");
        let original_name = process_info.process_name();
        process_info.set_process_name(new_name);
        assert_eq!(&*process_info.process_name(), new_name);
        process_info.set_process_name(&original_name);
        assert_eq!(&*process_info.process_name(), &*original_name);
    }

    #[test]
    fn test_processor_count() {
        let process_info = NSProcessInfo::process_info();
        let processor_count = process_info.processor_count();
        assert!(processor_count > 0);
    }

    #[test]
    fn test_active_processor_count() {
        let process_info = NSProcessInfo::process_info();
        let active_processor_count = process_info.active_processor_count();
        assert!(active_processor_count > 0);
    }

    #[test]
    fn test_system_uptime() {
        let process_info = NSProcessInfo::process_info();
        let system_uptime = process_info.system_uptime();

        #[cfg(feature = "gnustep-1-7")]
        assert!(system_uptime > 0);

        #[cfg(feature = "apple")]
        assert!(system_uptime > 0.)
    }

    #[test]
    fn test_debug() {
        let info = NSProcessInfo::process_info();
        let expected = format!(
            "NSProcessInfo {{ \
            process_name: {:?}, \
            host_name: {:?}, \
            operating_system_version_string: {:?}, \
            physical_memory: {:?}, \
            process_identifier: {:?}, \
            processor_count: {:?}, \
            .. }}",
            info.process_name(),
            info.host_name(),
            info.operating_system_version_string(),
            info.physical_memory(),
            info.process_identifier(),
            info.processor_count(),
        );
        assert_eq!(format!("{:?}", info), expected);
    }
}
