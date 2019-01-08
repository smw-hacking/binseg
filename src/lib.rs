//! A library for segmenting binary files. This can be useful in many cases like disecting
//! game rom files or old firmware packages.
//!
//! For the main part of this library go to the [segment_binary](macro.segment_binary.html) macro.

pub use crypto_hash;

/// Create a new binary segmenter for a binary with the given hash.
///
/// # Examples
/// Imagine a binary file with the following content (in hex):
/// ```bin
/// DEADBEEFBE57C0DE
/// ```
/// You can create a segmenter for getting the first and last part of this binary. For integrity
/// purposes, we first get the sha256 hash of the file:
/// ```shell
/// shasum -b -a 256 your_dir/binary_file.bin
/// ```
/// In this test case, the file lies in `test_bins/beef.bin`. Defining a segmenter works like this:
/// ```rust
/// use binseg::segment_binary;
///
/// segment_binary! {
///     pub BeefBin("8594c5c15c75fcc5f27893faa4b6a185ec6687306f92b81759d76704319a16b4") {
///         /// This beef is very dead
///         dead_beef: 0x00..0x04,
///         /// This code is the best
///         best_code: 0x04..0x08
///     }
/// }
///
/// # BeefBin::from_file("test_bins/beef.bin").unwrap();
/// ```
/// You can use the created segmenter by loading the designated file. The macro will create an
/// assotiated function for every section:
/// ```rust
/// # use binseg::segment_binary;
/// #
/// # segment_binary! {
/// #     pub BeefBin("8594c5c15c75fcc5f27893faa4b6a185ec6687306f92b81759d76704319a16b4") {
/// #         /// This beef is very dead
/// #         dead_beef: 0x00..0x04,
/// #         /// This code is the best
/// #         best_code: 0x04..0x08
/// #     }
/// # }
/// let seq_bin = BeefBin::from_file("test_bins/beef.bin").unwrap();
///
/// assert_eq!(seq_bin.dead_beef(), &[0xde, 0xad, 0xbe, 0xef]);
/// assert_eq!(seq_bin.best_code(), &[0xbe, 0x57, 0xc0, 0xde]);
/// ```
#[macro_export]
macro_rules! segment_binary {
    (
        pub $bin_ident:ident ( $hash_string:expr ) {
            $(
                $(#[$meta_attr:meta])*
                $seg_ident:ident : $mem_range:expr
            ),*
        }
    ) => (
        pub struct $bin_ident {
            bin_data: Vec<u8>
        }

        impl $bin_ident {
            #[doc = "Creates a new segmentation for the binary with the sha256 hash `"]
            #[doc = $hash_string]
            #[doc = "`"]
            pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> std::io::Result<$bin_ident> {
                use std::{io::Read, fs::File};
                use $crate::crypto_hash::{Algorithm, hex_digest};

                let mut file = File::open(path)?;
                let mut bin_data = Vec::new();

                file.read_to_end(&mut bin_data)?;

                let given_hash = String::from($hash_string);

                let actual_file_hash = hex_digest(Algorithm::SHA256, &bin_data);

                assert_eq!(actual_file_hash, given_hash, "incorrect file");

                Ok($bin_ident { bin_data })
            }

            $(
                $(#[$meta_attr])*
                pub fn $seg_ident(&self) -> &[u8] {
                    &self.bin_data[$mem_range]
                }
            )*
        }
    );
}
