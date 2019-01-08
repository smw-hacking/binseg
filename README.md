# binseg
A library for segmenting binaries

## Usage
First, generate a sha256 hash of the binary, you want to segment:
```shell
$ shasum -b -a 256 your/file.bin
8594c5c15c75fcc5f27893faa4b6a185ec6687306f92b81759d76704319a16b4 *your/file.bin
```

This hash is used as an automatic integrity check for the segmented file. Next, define your segmentation:
```rust
use binseg::segment_binary;

segment_binary! {
    pub BeefBin("8594c5c15c75fcc5f27893faa4b6a185ec6687306f92b81759d76704319a16b4") {
        /// Code comments will be attached to the generated function.
        dead_beef: 0x00..0x04,
        /// You can use them as documentation for the specified section.
        best_code: 0x04..0x08
    }
}
```

This will generate a `struct BeefBin` with a function `from_file` that takes some path. This means, that you can now load the file and have it automatically segmented by calling:
```rust
let my_bin = BeefBin::from_file("your/file.bin").unwrap();

println!("{:X?}", my_bin.dead_beef());
println!("{:X?}", my_bin.best_code());
```