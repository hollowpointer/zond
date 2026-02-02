// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

mod discovery;

#[cfg(target_os = "linux")]
pub mod utils {
    use std::process::Command;
    use std::thread;
    use std::time::Duration;

    /// RAII wrapper for a network namespace infrastructure.
    pub struct NetnsContext {
        pub ns_name: String,
        pub host_if: String,
        pub _target_if: String,
    }

    impl NetnsContext {
        pub fn new(suffix: &str) -> Option<Self> {
            let ns_name = format!("zond-ns-{}", suffix);
            let host_if = format!("v-host-{}", suffix);
            let target_if = format!("v-targ-{}", suffix);

            Self::cleanup(&ns_name, &host_if);

            if !run_cmd("ip", &["netns", "add", &ns_name]) {
                return None;
            }

            if !run_cmd(
                "ip",
                &[
                    "link", "add", &host_if, "type", "veth", "peer", "name", &target_if,
                ],
            ) {
                Self::cleanup(&ns_name, &host_if);
                return None;
            }

            if !run_cmd("ip", &["link", "set", &target_if, "netns", &ns_name]) {
                Self::cleanup(&ns_name, &host_if);
                return None;
            }

            run_cmd("ip", &["addr", "add", "10.200.0.1/24", "dev", &host_if]);
            run_cmd("ip", &["link", "set", &host_if, "up"]);

            run_ns_cmd(
                &ns_name,
                "ip",
                &["addr", "add", "10.200.0.2/24", "dev", &target_if],
            );
            run_ns_cmd(&ns_name, "ip", &["link", "set", &target_if, "up"]);
            run_ns_cmd(&ns_name, "ip", &["link", "set", "lo", "up"]);

            thread::sleep(Duration::from_millis(500));

            Some(Self {
                ns_name,
                host_if,
                _target_if: target_if,
            })
        }

        fn cleanup(ns_name: &str, host_if: &str) {
            let _ = Command::new("ip").args(["netns", "del", ns_name]).output();
            let _ = Command::new("ip").args(["link", "del", host_if]).output();
        }
    }

    impl Drop for NetnsContext {
        fn drop(&mut self) {
            Self::cleanup(&self.ns_name, &self.host_if);
        }
    }

    fn run_cmd(cmd: &str, args: &[&str]) -> bool {
        let status = Command::new(cmd).args(args).status();
        match status {
            Ok(s) => s.success(),
            Err(_) => false,
        }
    }

    fn run_ns_cmd(ns: &str, cmd: &str, args: &[&str]) -> bool {
        let mut final_args = vec!["netns", "exec", ns, cmd];
        final_args.extend_from_slice(args);
        run_cmd("ip", &final_args)
    }
}
