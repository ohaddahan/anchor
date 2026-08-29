/// Emit a minimal Solana security.txt record containing only release and
/// revision provenance fields.
#[macro_export]
macro_rules! program_security_txt {
    ($($fields:tt)*) => {
        $crate::__anchor_private_security_txt!(@collect [none] [none]; $($fields)*);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __anchor_private_security_txt {
    (@collect [$($release:tt)*] [$($revision:tt)*];) => {
        $crate::__anchor_private_security_txt!(@emit [$($release)*] [$($revision)*]);
    };
    (@collect [$($release:tt)*] [$($revision:tt)*]; source_release: $value:expr) => {
        $crate::__anchor_private_security_txt!(@emit [some $value] [$($revision)*]);
    };
    (@collect [$($release:tt)*] [$($revision:tt)*]; source_revision: $value:expr) => {
        $crate::__anchor_private_security_txt!(@emit [$($release)*] [some $value]);
    };
    (@collect [$($release:tt)*] [$($revision:tt)*]; $name:ident: $value:expr) => {
        $crate::__anchor_private_security_txt!(@emit [$($release)*] [$($revision)*]);
    };
    (@collect [$($release:tt)*] [$($revision:tt)*]; source_release: $value:expr, $($rest:tt)*) => {
        $crate::__anchor_private_security_txt!(@collect [some $value] [$($revision)*]; $($rest)*);
    };
    (@collect [$($release:tt)*] [$($revision:tt)*]; source_revision: $value:expr, $($rest:tt)*) => {
        $crate::__anchor_private_security_txt!(@collect [$($release)*] [some $value]; $($rest)*);
    };
    (@collect [$($release:tt)*] [$($revision:tt)*]; $name:ident: $value:expr, $($rest:tt)*) => {
        $crate::__anchor_private_security_txt!(@collect [$($release)*] [$($revision)*]; $($rest)*);
    };
    (@emit [none] [none]) => {
        $crate::__anchor_private_security_txt!(@static "");
    };
    (@emit [some $release:expr] [none]) => {
        $crate::__anchor_private_security_txt!(@static "source_release\0", $release, "\0");
    };
    (@emit [none] [some $revision:expr]) => {
        $crate::__anchor_private_security_txt!(@static "source_revision\0", $revision, "\0");
    };
    (@emit [some $release:expr] [some $revision:expr]) => {
        $crate::__anchor_private_security_txt!(@static
            "source_release\0", $release, "\0",
            "source_revision\0", $revision, "\0"
        );
    };
    (@static $($contents:expr),*) => {
        #[cfg_attr(any(target_arch = "bpf", target_os = "solana"), link_section = ".security.txt")]
        #[allow(dead_code)]
        #[no_mangle]
        pub static SECURITY_TXT: &str = concat!(
            "=======BEGIN SECURITY.TXT V1=======\0",
            $($contents,)*
            "=======END SECURITY.TXT V1=======\0"
        );
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __anchor_log_instruction {
    ($name:expr) => {};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __anchor_entrypoint {
    ($process_instruction:ident) => {
        /// # Safety
        #[no_mangle]
        pub unsafe extern "C" fn entrypoint(input: *mut u8) -> u64 {
            let (program_id, accounts, instruction_data) =
                unsafe { $crate::solana_program::entrypoint::deserialize(input) };
            match $process_instruction(program_id, &accounts, instruction_data) {
                Ok(()) => $crate::solana_program::entrypoint::SUCCESS,
                Err(error) => error.into(),
            }
        }

        $crate::solana_program::entrypoint::custom_heap_default!();

        #[cfg(all(not(feature = "custom-panic"), target_os = "solana"))]
        #[no_mangle]
        fn custom_panic(_: &core::panic::PanicInfo<'_>) {}
    };
}
