pub mod core;

/** Debug output macro
 * This will always print in debug builds AND in release builds with verbose feature
 * */
#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        #[cfg(any(debug_assertions, feature = "verbose"))]
        println!("[DEBUG] {}", format_args!($($arg)*));
    };
}
