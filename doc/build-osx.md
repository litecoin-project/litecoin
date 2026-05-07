# macOS Build Instructions and Notes

## Build Options

Litecoin Core can be built with different features enabled or disabled. The table below shows which packages are required for each build configuration.

| Feature | Configure Flag | Required Packages |
|---------|---------------|-------------------|
| Headless daemon | (default) | Core dependencies |
| Wallet (BDB) | (default, or `--with-sqlite=no`) | Core + `berkeley-db@4` |
| Wallet (BDB + SQLite) | `--with-sqlite=yes` | Core + `berkeley-db@4` + `sqlite` |
| No wallet | `--disable-wallet` | Core only |
| GUI | (default if Qt found) | Core + Wallet + `qt@5` + `qrencode` |
| No GUI | `--without-gui` | (removes Qt requirement) |
| UPnP support | (default if found) | `miniupnpc` |
| No UPnP | `--without-miniupnpc` | (removes miniupnpc requirement) |
| ZMQ notifications | (default if found) | `zeromq` |
| Disk image (.dmg) | `make deploy` | `librsvg` |
| Multiprocess | `--enable-multiprocess` | `capnp` + `libmultiprocess` (see below) |

## Preparation

The commands in this guide should be executed in a Terminal application.
The built-in one is located in
```
/Applications/Utilities/Terminal.app
```

Install the macOS command line tools:

```shell
xcode-select --install
```

When the popup appears, click `Install`.

Then install [Homebrew](https://brew.sh).

## Dependencies

### Intel Mac Note

On Intel Macs, Homebrew installs to `/usr/local` instead of `/opt/homebrew`. Replace all instances of `/opt/homebrew` with `/usr/local` in the commands.

### Core Dependencies (Required for all builds)

```shell
brew install automake autoconf libtool boost pkg-config python libevent openssl fmt 
```

### Optional Dependencies

Install based on which features you want:

```shell
# ZMQ notification support (recommended)
brew install zeromq

# UPnP support (optional)
brew install miniupnpc
```

If you want to build the disk image with `make deploy`, you need RSVG to create the `.dmg` disk image.

```shell
brew install librsvg
```

If you run into issues, check [Homebrew's troubleshooting page](https://docs.brew.sh/Troubleshooting).
See [dependencies.md](dependencies.md) for a complete overview.

### Wallet Dependencies

Wallet support requires Berkeley DB 4.8. SQLite support is optional and enables descriptor wallets.

#### Berkeley DB (Required for wallet)

```shell
brew install berkeley-db@4
```

Alternatively, you can build Berkeley DB 4.8 from source using the included script:

```shell
./contrib/install_db4.sh .
```

#### SQLite

Usually, macOS installation already has a suitable SQLite installation.
Also, the Homebrew package could be installed:

```shell
brew install sqlite
```

**Note:** SQLite is "keg-only" in Homebrew, meaning it requires special path configuration (handled automatically by the build commands below).

In that case the Homebrew package will prevail.


### GUI Dependencies

For the graphical interface:

```shell
brew install qt@5 qrencode
```

**Note:** Qt5 is "keg-only" in Homebrew, meaning it requires special path configuration (handled automatically by the build commands below).

**Intel Mac Note:** On Intel Macs, full Xcode (not just Command Line Tools) may be required for building the Qt GUI, especially on older macOS versions.

### Multiprocess Dependencies (Optional - Experimental)

The multiprocess feature allows running the node and wallet in separate processes for better isolation. This requires Cap'n Proto and libmultiprocess.

```shell
# Install Cap'n Proto and cmake
brew install capnp cmake

# Build and install libmultiprocess from source
cd /tmp
git clone https://github.com/chaincodelabs/libmultiprocess.git
cd libmultiprocess
mkdir build && cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/opt/homebrew
make -j$(sysctl -n hw.ncpu)
make check    # Optional: run tests
make install  # Install to /opt/homebrew
```

**Note:** libmultiprocess is not available in Homebrew and must be built from source.

## Build Litecoin Core

### Quick Start - Full Build (GUI + Wallet)

Install all dependencies:

```shell
brew install autoconf automake libtool pkg-config boost libevent openssl fmt zeromq berkeley-db@4 sqlite qt@5 qrencode
```

Build:

```shell
# Set up paths for keg-only packages
export PATH="/opt/homebrew/bin:/opt/homebrew/opt/qt@5/bin:$PATH"
export PKG_CONFIG_PATH="/opt/homebrew/opt/sqlite/lib/pkgconfig:/opt/homebrew/opt/qt@5/lib/pkgconfig:$PKG_CONFIG_PATH"

# Clone and build
git clone https://github.com/Litecoin-project/litecoin
cd litecoin

./autogen.sh

./configure \
  --with-boost=/opt/homebrew \
  --with-qt-translationdir=$(brew --prefix qt@5)/translations \
  LDFLAGS="-L/opt/homebrew/lib -L/opt/homebrew/opt/sqlite/lib -L/opt/homebrew/opt/qt@5/lib" \
  CPPFLAGS="-I/opt/homebrew/include -I/opt/homebrew/opt/sqlite/include -I/opt/homebrew/opt/qt@5/include"

make -j$(sysctl -n hw.ncpu)
```

### Headless Build (No GUI, with Wallet)

```shell
# Install dependencies
brew install autoconf automake libtool pkg-config boost libevent openssl fmt zeromq berkeley-db@4

# Set up paths
export PATH="/opt/homebrew/bin:$PATH"

# Build
./autogen.sh

./configure \
  --without-gui \
  --with-boost=/opt/homebrew \
  LDFLAGS="-L/opt/homebrew/lib" \
  CPPFLAGS="-I/opt/homebrew/include"

make -j$(sysctl -n hw.ncpu)
```

### Minimal Build (No GUI, No Wallet)

```shell
# Install dependencies
brew install autoconf automake libtool pkg-config boost libevent openssl fmt zeromq

# Set up paths
export PATH="/opt/homebrew/bin:$PATH"

# Build
./autogen.sh

./configure \
  --disable-wallet \
  --without-gui \
  --without-miniupnpc \
  --with-boost=/opt/homebrew \
  LDFLAGS="-L/opt/homebrew/lib" \
  CPPFLAGS="-I/opt/homebrew/include"

make -j$(sysctl -n hw.ncpu)
```

### Multiprocess Build (Experimental)

This builds separate `litecoin-node` and `litecoin-wallet` executables that communicate via IPC, providing better process isolation.

**Intel Mac Note:** For multiprocess or fuzzing builds, you may need to use
Homebrew’s Clang (`/usr/local/opt/llvm/bin/clang`) instead of the system Clang,
which may be too old or lack required features.

First, install libmultiprocess (see [Multiprocess Dependencies](#multiprocess-dependencies-optional---experimental) above).

```shell
# Install dependencies (including wallet support)
brew install autoconf automake libtool pkg-config boost libevent openssl fmt zeromq berkeley-db@4 sqlite capnp

# Set up paths (include libmultiprocess pkgconfig)
export PATH="/opt/homebrew/bin:$PATH"
export PKG_CONFIG_PATH="/opt/homebrew/lib/pkgconfig:/opt/homebrew/opt/sqlite/lib/pkgconfig:$PKG_CONFIG_PATH"

# Build
./autogen.sh

./configure \
  --enable-multiprocess \
  --without-gui \
  --with-boost=/opt/homebrew \
  LDFLAGS="-L/opt/homebrew/lib -L/opt/homebrew/opt/sqlite/lib" \
  CPPFLAGS="-I/opt/homebrew/include -I/opt/homebrew/opt/sqlite/include"

make -j$(sysctl -n hw.ncpu)
```

This produces additional binaries:
- `litecoin-node` - Multiprocess node executable (P2P + RPC)
- `litecoin-wallet` - Multiprocess wallet executable (communicates with node via IPC)

### Intel Mac Note

On Intel Macs, Homebrew installs to `/usr/local` instead of `/opt/homebrew`. Replace all instances of `/opt/homebrew` with `/usr/local` in the commands above.

## Running Tests

It is recommended to build and run the unit tests:

```shell
make check
```

## Creating a Disk Image

You can create a `.dmg` that contains the `.app` bundle:

```shell
make deploy
```

**Note:** When building with Qt GUI support, you must configure the Qt translation directory for `make deploy` to work. This is included in the [Quick Start build instructions](#quick-start---full-build-gui--wallet) above using `--with-qt-translationdir=$(brew --prefix qt@5)/translations`. If you didn't include this during configure, you'll need to reconfigure with this option.

Some Qt translation files may be missing from Homebrew's Qt5 installation (notably Portuguese). The deployment script will skip missing translations with a warning, which is safe since the application handles missing translations gracefully.

## Running

Litecoin Core is now available at `./src/litecoind`

Before running, you may create an empty configuration file:

```shell
mkdir -p "/Users/${USER}/Library/Application Support/Litecoin"

touch "/Users/${USER}/Library/Application Support/Litecoin/litecoin.conf"

chmod 600 "/Users/${USER}/Library/Application Support/Litecoin/litecoin.conf"
```

The first time you run litecoind, it will start downloading the blockchain. This process could
take many hours, or even days on slower than average systems.

You can monitor the download process by looking at the debug.log file:

```shell
tail -f $HOME/Library/Application\ Support/Litecoin/debug.log
```

## Other commands

```shell
./src/litecoind -daemon      # Starts the litecoin daemon.
./src/litecoin-cli --help    # Outputs a list of command-line options.
./src/litecoin-cli help      # Outputs a list of RPC commands when the daemon is running.
./src/litecoin-qt            # Starts the GUI (if built with Qt support).

# Multiprocess binaries (if built with --enable-multiprocess):
./src/litecoin-node          # Multiprocess node (drop-in replacement for litecoind).
./src/litecoin-wallet        # Multiprocess wallet.
```

## Troubleshooting

### Boost::System library not found

If you encounter an error about `Boost::System library not found` during configure, this is because Boost 1.69+ made `boost::system` header-only. The build system has been updated to handle this automatically.

### Qt, FMT or SQLite not found

These packages are "keg-only" in Homebrew, meaning they are not symlinked to standard paths. Make sure you've set the `PKG_CONFIG_PATH`, `LDFLAGS`, and `CPPFLAGS` environment variables as shown in the build commands above.

### Permission errors during build

If you encounter permission errors, ensure you have write access to the build directory and that no other process is using the files.

## Notes

* Tested on macOS 14 Sonoma and macOS 15 on Apple Silicon (ARM64) and macOS 10.14 Mojave through macOS 11 Big Sur on Intel (x86_64).
* Building with downloaded Qt binaries is not officially supported. See the notes in [#7714](https://github.com/bitcoin/bitcoin/issues/7714).
* The `--with-incompatible-bdb` flag can be used if you need to use a Berkeley DB version other than 4.8, but this is not recommended for production wallets.

## Fuzzing (Advanced)

To build with fuzzing support (`--enable-fuzz`), you need the full LLVM toolchain (not Apple's default clang):

```shell
# Install full LLVM
brew install llvm

# Configure with LLVM's clang and libc++
CC=/opt/homebrew/opt/llvm/bin/clang \
CXX=/opt/homebrew/opt/llvm/bin/clang++ \
./configure \
  --enable-fuzz \
  --with-sanitizers=fuzzer,address,undefined \
  --disable-asm \
  --without-gui \
  --with-boost=/opt/homebrew \
  LDFLAGS="-L/opt/homebrew/lib -L/opt/homebrew/opt/llvm/lib/c++ -L/opt/homebrew/opt/llvm/lib/unwind -lunwind -stdlib=libc++" \
  CPPFLAGS="-I/opt/homebrew/include" \
  CXXFLAGS="-stdlib=libc++"
```

**Note:** Apple's default clang does not include libFuzzer. You must use Homebrew's LLVM with its bundled libc++. See [doc/fuzzing.md](fuzzing.md) for more details.

