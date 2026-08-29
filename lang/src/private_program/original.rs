/// Emit a standard Solana security.txt record.
#[macro_export]
macro_rules! program_security_txt {
    ($($field:ident: $value:expr),* $(,)?) => {
        $crate::__private::solana_security_txt::security_txt!($($field: $value),*);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __anchor_log_instruction {
    ($name:expr) => {
        $crate::prelude::msg!($name)
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __anchor_entrypoint {
    ($process_instruction:ident) => {
        $crate::solana_program::entrypoint!($process_instruction);
    };
}
