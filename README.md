<div align="center">
  <img src="doc/images/penguincoin-logo.png" alt="PenguinCoin Logo" width="200"/>
  <h1>PenguinCoin Core</h1>
  <p>A peer-to-peer digital currency for the global economy</p>

  [![Build Status](https://travis-ci.org/penguincoin-project/penguincoin.svg?branch=master)](https://travis-ci.org/penguincoin-project/penguincoin)
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
  [![GitHub Release](https://img.shields.io/github/release/penguincoin-project/penguincoin.svg)](https://github.com/penguincoin-project/penguincoin/releases)
  [![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-v2.0%20adopted-ff69b4.svg)](CODE_OF_CONDUCT.md)
</div>

## Table of Contents
- [What is PenguinCoin?](#what-is-penguincoin)
- [Key Features](#key-features)
- [Getting Started](#getting-started)
- [Documentation](#documentation)
- [Development](#development)
- [Testing](#testing)
- [Contributing](#contributing)
- [Community](#community)
- [License](#license)

## What is PenguinCoin?

PenguinCoin is an innovative digital currency that enables instant payments to anyone, anywhere in the world. Built on peer-to-peer technology, PenguinCoin operates with no central authority: transaction management and money issuance are carried out collectively by the network. PenguinCoin Core is the name of the open source software which enables the use of this currency.

Visit our website at [https://penguincoin.org](https://penguincoin.org) for more information.

## Key Features

- **Decentralized**: No central authority controls PenguinCoin
- **Secure**: Built with state-of-the-art cryptography
- **Fast**: Near-instant transactions worldwide
- **Low Fees**: Send money globally for pennies
- **Privacy-Focused**: Control your financial information
- **Open Source**: Transparent code anyone can verify

## Getting Started

### Binary Downloads

For most users, we recommend downloading pre-compiled binaries:

- [Download PenguinCoin Core](https://penguincoin.org/downloads) - Official releases for Windows, macOS, and Linux

### Building from Source

For developers or advanced users who want to build from source:

1. Clone this repository
2. Follow the build instructions for your platform:
   - [Unix Build Notes](doc/build-unix.md)
   - [Windows Build Notes](doc/build-windows.md)
   - [macOS Build Notes](doc/build-osx.md)

## Documentation

- [PenguinCoin Wiki](https://github.com/penguincoin-project/penguincoin/wiki)
- [Setup Instructions](doc/README.md)
- [Developer Documentation](doc/developer-notes.md)

## Development

PenguinCoin Core development follows an open process. Anyone can contribute code or documentation through pull requests on GitHub.

### Repository Organization

The `master` branch is regularly built and tested, but is not guaranteed to be stable. For production use, refer to the [release tags](https://github.com/penguincoin-project/penguincoin/tags) which indicate stable versions.

The GUI is developed in the separate [penguincoin-project/gui](https://github.com/penguincoin-project/gui) repository.

### Development Process

Our development workflow is described in detail in [CONTRIBUTING.md](CONTRIBUTING.md). Key points:

- Code changes happen through pull requests
- All PRs need review and approval
- Continuous integration ensures quality
- Semantic versioning is used for releases

## Testing

Quality assurance is critical for a currency system. We employ several testing strategies:

### Automated Testing

- **Unit Tests**: Run with `make check`
- **Functional Tests**: Run with `test/functional/test_runner.py`

Developers are encouraged to write tests for new code. See [src/test/README.md](src/test/README.md) for more information.

### Manual QA Testing

Changes should be tested by someone other than the developer who wrote the code, especially for large or high-risk changes. Adding a test plan to pull requests helps reviewers.

## Contributing

We welcome contributions from everyone! Please read our [contribution guidelines](CONTRIBUTING.md) before submitting pull requests.

- 👾 **Code**: Bug fixes, new features, performance improvements
- 📚 **Documentation**: Help improve our docs or translations
- 🧪 **Testing**: Report bugs or test new features
- 💡 **Ideas**: Suggest improvements or new features

## Community

- [PenguinCoin Forum](https://forum.penguincoin.org)
- [Developer Mailing List](https://groups.google.com/forum/#!forum/penguincoin-dev)
- [IRC](irc://irc.freenode.net/penguincoin-dev) (#penguincoin-dev on Freenode)
- [Twitter](https://twitter.com/PenguinCoinOrg)
- [Reddit](https://reddit.com/r/penguincoin)

## Translations

We only accept translation fixes submitted through [Bitcoin Core's Transifex page](https://www.transifex.com/projects/p/bitcoin/). Translations are periodically pulled and merged into the repository following the [translation process](doc/translation_process.md).

**Important**: We do not accept translation changes as GitHub pull requests.

## License

PenguinCoin Core is released under the terms of the MIT license. See [COPYING](COPYING) for more information or visit https://opensource.org/licenses/MIT.
