# BrewHouse

A modern GTK4/libadwaita GUI for managing Homebrew packages on Linux.

## Features

- **Installed Packages**: View all installed Homebrew formulae with details (version, description, homepage)
- **Browse & Search**: Search the Homebrew repository and install new packages
- **Updates**: View outdated packages and upgrade individually or all at once
- **Status Overview**: Quick stats showing installed packages, casks, outdated items, and more

## Screenshots

The application uses a clean sidebar navigation with three main views:

- Installed: List and manage your installed packages
- Browse: Search and install new packages
- Updates: Check for and apply package updates

## Requirements

### System Dependencies

**Ubuntu/Debian:**

```bash
sudo apt install libgtk-4-dev libadwaita-1-dev
```

**Fedora:**

```bash
sudo dnf install gtk4-devel libadwaita-devel
```

**Arch Linux:**

```bash
sudo pacman -S gtk4 libadwaita
```

### Homebrew

BrewHouse requires [Homebrew](https://brew.sh/) to be installed:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

### Rust

Install Rust via [rustup](https://rustup.rs/):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Building

```bash
# Clone the repository
git clone https://github.com/dlbradford/brewhouse.git
cd brewhouse

# Build in release mode
cargo build --release

# The binary will be at target/release/brewhouse
```

## Running

```bash
cargo run --release
```

Or run the binary directly:

```bash
./target/release/brewhouse
```

## Usage

1. **On startup**, BrewHouse runs `brew update` to ensure your package index is current
2. **Installed tab**: Browse your installed packages, view details, and uninstall if needed
3. **Browse tab**: Search for packages by name, view info, and install with one click
4. **Updates tab**: See which packages have updates available; upgrade selected packages or all at once

## Dependencies

- [gtk4](https://crates.io/crates/gtk4) - GTK4 Rust bindings
- [libadwaita](https://crates.io/crates/libadwaita) - Adwaita widgets for GTK4
- [serde](https://crates.io/crates/serde) / [serde_json](https://crates.io/crates/serde_json) - JSON parsing for brew output
- [tokio](https://crates.io/crates/tokio) - Async runtime for non-blocking brew commands

## License

MIT

## Caveats

This was not written by a developer. Just a retired person who has the time and an idea. It was coded by Claude Code. I find it very useful for keeping my brew installs in good shape. I've done ZERO security on this, if you want to harden it or something, have at it.
