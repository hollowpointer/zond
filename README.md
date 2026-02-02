# Zond

**Zond** is a lightweight, fast network mapping and discovery tool designed for Linux and macOS.

<img width="1920" height="1080" alt="github" src="https://github.com/user-attachments/assets/60bd1b8d-a9c8-4fea-9339-85e31ba97504" />

## Compatibility

* **Supported Platforms:** Linux, macOS
* **Unsupported:** Windows is not currently supported.

## Installation

### Arch Linux (AUR)

Zond is available on the AUR. You can install it using an AUR helper like `yay`:

```bash
yay -S zond

```

### Building from Source

For other Linux distributions and macOS, you must build the tool from source. Ensure you have the [Rust toolchain](https://www.rust-lang.org/tools/install) installed.

1. **Clone the repository:**
```bash
git clone https://github.com/hollowpointer/zond
cd zond

```


2. **Build the release executable:**
```bash
cargo build --release

```


3. **Locate the binary:**
The compiled binary will be available in `target/release/zond`. You may move this to your `/usr/local/bin` or add it to your `$PATH`.

## Usage

**Note on Privileges:** Network discovery operations utilizing raw sockets typically require root privileges. Most discovery commands should be prefixed with `sudo`.

### 1. Network Discovery

The `discover` command (alias: `d`) scans targets for active hosts. It retrieves IP addresses (IPv4/IPv6), MAC addresses, vendors, and hostnames.

**Syntax:**

```bash
sudo zond discover <target> [flags]

```

**Examples:**

* **Automatic LAN Scan:** Detects the local subnet and scans for active hosts.
```bash
sudo zond d lan

```


* **Complex Ranges & Subnets:** Zond supports CIDR notation and mixed targets in a single command.
```bash
sudo zond d 1.1.1.1/28 1.1.1.128/26

```


* **Range Shorthand:** Use hyphens to define ranges. If the end of the range is a partial octet, Zond automatically fills the preceding octets from the start address.
```bash
# Scans from 10.0.0.1 to 10.0.2.128
sudo zond d 10.0.0.1-2.128

```



### 2. System Information

The `info` command (alias: `i`) displays detailed configuration regarding the local machine. This includes:

* Network Interfaces
* Firewall Status
* Local Services (Open ports/processes on TCP/UDP)
* System Details (OS, Kernel, Hostname)

**Example:**

```bash
sudo zond i

```

## Options & Flags

Zond provides several flags to customize output density, logging levels, and privacy settings.

| Flag | Description |
| --- | --- |
| `-n`, `--no-dns` | Disables sending of DNS packets. |
| `--no-banner` | Keep logs and colors but hide the ASCII art. |
| `-q`, `--quiet` | Reduce UI visual density. Use `-q` to reduce styling or `-qq` for raw IP output. |
| `--redact` | Redact sensitive info (IPv6 suffixes, MAC addresses, etc.). |
| `-v`, `--verbose` | Increase logging detail. Use `-v` for debug logs or `-vv` for full packet logs. |
| `-h`, `--help` | Print help. |

## License

This project is licensed under the **Mozilla Public License 2.0** (MPL-2.0).
See the [LICENSE](LICENSE) file for more details.

Copyright (c) 2026 OverTheFlow and Contributors.
