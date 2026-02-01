/// Global configuration options for the scanner execution.
///
/// This struct controls the runtime behavior of the application, including
/// UI verbosity, network protocol constraints, and privacy features.
/// It is typically constructed via CLI arguments or a configuration file.
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// Toggles the display of the startup ASCII banner.
    ///
    /// If `true`, the application starts immediately with log output/spinners
    /// without printing the stylized branding. Useful for clean logs or
    /// frequent executions.
    pub no_banner: bool,

    /// Restricts the scanner from generating outbound DNS traffic.
    ///
    /// # Behavior
    /// * **True**: The scanner will strictly avoid sending DNS queries (A, AAAA, PTR).
    /// * **False** (Default): The scanner may resolve hostnames to IPs or perform reverse lookups.
    ///
    /// **Note:** This does not prevent the underlying OS or network stack from
    /// processing incoming DNS packets if they were initiated elsewhere.
    pub no_dns: bool,

    /// Enables privacy mode for sensitive data in the output.
    ///
    /// When enabled, personally identifiable information (PII) or sensitive
    /// network details are masked.
    ///
    /// # Masked Fields
    /// * IPv6 Suffixes (e.g Global Unicast)
    /// * MAC Addresses
    /// * Hostnames
    ///
    /// Use this when sharing screenshots or logs publicly.
    pub redact: bool,

    /// Controls the visual density and formatting of the terminal output.
    ///
    /// This value is typically mapped from the `-q` or `--quiet` CLI flags.
    ///
    /// # Levels
    /// * **0** (Default): Full UI, including colors, spinners, and detailed tables.
    /// * **1**: Reduced styling. Minimal colors, simplified tables.
    /// * **2**: Raw mode. Output is strictly data (e.g., plain IP lists), suitable for piping into other tools.
    pub quiet: u8,

    /// Disables interactive keyboard listeners.
    ///
    /// When `true`, the application will not spawn threads to listen for
    /// runtime commands (like pausing, resuming, or status checks).
    ///
    /// # Use Cases
    /// * Running in a CI/CD pipeline.
    /// * Running as a background system service (daemon).
    /// * Non-interactive testing environments.
    pub disable_input: bool,
}
