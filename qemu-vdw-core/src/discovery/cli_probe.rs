//! [`CliProbeDiscoverer`]: the first [`RootDeviceDiscoverer`] implementation,
//! wrapping the already-installed `blkid`, `cryptsetup`, and `lvs` binaries
//! (see design.md Decision 4) instead of native `libblkid`/`libudev`
//! bindings.

use std::io;
use std::process::{Command, Output};

use super::{DeviceKind, DiscoveryError, PassthroughDevice, RootDeviceDiscoverer};

/// Abstraction over spawning a subprocess and capturing its output.
///
/// Production code uses [`SystemCommandRunner`]; unit tests inject a fake
/// implementation returning canned [`Output`]s so discovery logic can be
/// exercised without any real block devices or even the real binaries
/// being present (per the "fixture-based unit tests" guidance in tasks.md).
pub trait CommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> io::Result<Output>;
}

/// Runs real subprocesses via [`std::process::Command`].
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> io::Result<Output> {
        Command::new(program).args(args).output()
    }
}

/// [`RootDeviceDiscoverer`] implementation wrapping `blkid -o export`,
/// `cryptsetup isLuks`, and `lvs --reportformat json`.
pub struct CliProbeDiscoverer<R: CommandRunner = SystemCommandRunner> {
    runner: R,
    blkid_bin: String,
    cryptsetup_bin: String,
    lvs_bin: String,
}

impl CliProbeDiscoverer<SystemCommandRunner> {
    /// Build a discoverer that shells out to the `blkid`, `cryptsetup`, and
    /// `lvs` binaries found on `$PATH`.
    pub fn new() -> Self {
        Self::with_runner(SystemCommandRunner)
    }
}

impl Default for CliProbeDiscoverer<SystemCommandRunner> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: CommandRunner> CliProbeDiscoverer<R> {
    /// Build a discoverer around a custom [`CommandRunner`] (used by tests).
    pub fn with_runner(runner: R) -> Self {
        Self {
            runner,
            blkid_bin: "blkid".to_string(),
            cryptsetup_bin: "cryptsetup".to_string(),
            lvs_bin: "lvs".to_string(),
        }
    }

    /// Override the `blkid` binary name/path (mainly for tests simulating
    /// a missing tool).
    pub fn with_blkid_bin(mut self, bin: impl Into<String>) -> Self {
        self.blkid_bin = bin.into();
        self
    }

    /// Override the `cryptsetup` binary name/path.
    pub fn with_cryptsetup_bin(mut self, bin: impl Into<String>) -> Self {
        self.cryptsetup_bin = bin.into();
        self
    }

    /// Override the `lvs` binary name/path.
    pub fn with_lvs_bin(mut self, bin: impl Into<String>) -> Self {
        self.lvs_bin = bin.into();
        self
    }

    fn spawn(&self, tool: &'static str, program: &str, args: &[&str]) -> Result<Output, DiscoveryError> {
        self.runner
            .run(program, args)
            .map_err(|source| DiscoveryError::ToolUnavailable { tool, source })
    }

    /// `blkid -o export` lists every recognizable block device as
    /// blank-line-separated `KEY=value` blocks. Returns `(devname, type)`
    /// pairs for every block that has a `DEVNAME`.
    fn list_blkid_devices(&self) -> Result<Vec<(String, Option<String>)>, DiscoveryError> {
        let blkid_bin = self.blkid_bin.clone();
        let output = self.spawn("blkid", &blkid_bin, &["-o", "export"])?;
        // blkid exits 2 when it has nothing to report at all; that's a
        // legitimate "no devices found" result, not a tool failure.
        if !output.status.success() && output.status.code() != Some(2) {
            return Err(DiscoveryError::ToolFailed {
                tool: "blkid",
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        let stdout = String::from_utf8(output.stdout).map_err(|e| DiscoveryError::ParseError {
            tool: "blkid",
            reason: format!("output was not valid UTF-8: {e}"),
        })?;
        Ok(parse_blkid_export(&stdout))
    }

    /// `cryptsetup isLuks <dev>`: exit 0 means the device is a LUKS
    /// container. `cryptsetup` uses distinct non-zero exit codes for "not
    /// LUKS" (1), "device does not exist or access denied" (4), and other
    /// conditions — but as a read-only *classification* predicate we treat
    /// every non-zero exit the same way (not confirmed LUKS) rather than
    /// hard-failing the whole discovery run over one device this caller
    /// happens not to have raw read access to (an expected situation for
    /// unprivileged callers, confirmed against a real multi-device host).
    fn is_luks(&self, devname: &str) -> Result<bool, DiscoveryError> {
        let cryptsetup_bin = self.cryptsetup_bin.clone();
        let output = self.spawn("cryptsetup", &cryptsetup_bin, &["isLuks", devname])?;
        Ok(output.status.code() == Some(0))
    }

    /// `lvs --reportformat json -o vg_name,lv_name,devices`: read-only LVM
    /// metadata scan (does not activate anything). Returns
    /// `(pv_device, volume_group, logical_volume)` triples.
    ///
    /// `lvs` commonly exits non-zero for an unprivileged caller (e.g.
    /// `WARNING: Running as a non-root user. Functionality may be
    /// unavailable.` / lock-file permission errors reported via its `log`
    /// array) while still emitting well-formed, usable JSON on stdout —
    /// confirmed against a real multi-user host. So the exit code alone
    /// isn't a reliable failure signal here: only treat this as a tool
    /// failure if the output *also* fails to parse as the expected report.
    fn list_lvm_devices(&self) -> Result<Vec<(String, String, String)>, DiscoveryError> {
        let lvs_bin = self.lvs_bin.clone();
        let output = self.spawn(
            "lvs",
            &lvs_bin,
            &["--reportformat", "json", "-o", "vg_name,lv_name,devices"],
        )?;
        let stdout = String::from_utf8(output.stdout).map_err(|e| DiscoveryError::ParseError {
            tool: "lvs",
            reason: format!("output was not valid UTF-8: {e}"),
        })?;
        let parsed: LvsRoot = serde_json::from_str(&stdout).map_err(|e| {
            if output.status.success() {
                DiscoveryError::ParseError {
                    tool: "lvs",
                    reason: e.to_string(),
                }
            } else {
                DiscoveryError::ToolFailed {
                    tool: "lvs",
                    stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                }
            }
        })?;
        let mut result = Vec::new();
        for block in parsed.report {
            for row in block.lv {
                if let Some(pv) = pv_device_from_devices_field(&row.devices) {
                    result.push((pv.to_string(), row.vg_name, row.lv_name));
                }
            }
        }
        Ok(result)
    }
}

impl<R: CommandRunner> RootDeviceDiscoverer for CliProbeDiscoverer<R> {
    fn discover(&self) -> Result<Vec<PassthroughDevice>, DiscoveryError> {
        let blkid_devices = self.list_blkid_devices()?;
        if blkid_devices.is_empty() {
            return Ok(Vec::new());
        }

        let needs_lvm_lookup = blkid_devices
            .iter()
            .any(|(_, ty)| ty.as_deref() == Some("LVM2_member"));
        let lvm_index = if needs_lvm_lookup {
            self.list_lvm_devices()?
        } else {
            Vec::new()
        };

        let mut results = Vec::new();
        for (devname, ty) in blkid_devices {
            // cryptsetup is authoritative for LUKS; only pay for the extra
            // subprocess when blkid's TYPE is crypto_LUKS or unset (blkid
            // versions vary in whether they always tag LUKS containers).
            let looks_luks = matches!(ty.as_deref(), Some("crypto_LUKS") | None);
            if looks_luks && self.is_luks(&devname)? {
                results.push(PassthroughDevice::new(devname, DeviceKind::Luks));
                continue;
            }

            match ty.as_deref() {
                Some("LVM2_member") => {
                    if let Some((_, vg, lv)) = lvm_index.iter().find(|(pv, _, _)| pv == &devname) {
                        results.push(PassthroughDevice::new(
                            devname,
                            DeviceKind::Lvm {
                                volume_group: vg.clone(),
                                logical_volume: lv.clone(),
                            },
                        ));
                    }
                    // else: a PV with no resolvable VG/LV yet -> not
                    // eligible for passthrough on its own, skip it.
                }
                Some(other) if !other.is_empty() => {
                    results.push(PassthroughDevice::new(devname, DeviceKind::Plain));
                }
                _ => {
                    // No recognizable signature -> not eligible, skip.
                }
            }
        }
        Ok(results)
    }
}

fn parse_blkid_export(input: &str) -> Vec<(String, Option<String>)> {
    let mut devices = Vec::new();
    let mut devname: Option<String> = None;
    let mut ty: Option<String> = None;

    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() {
            if let Some(d) = devname.take() {
                devices.push((d, ty.take()));
            }
            ty = None;
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            match key {
                "DEVNAME" => devname = Some(value.to_string()),
                "TYPE" => ty = Some(value.to_string()),
                _ => {}
            }
        }
    }
    if let Some(d) = devname.take() {
        devices.push((d, ty.take()));
    }
    devices
}

/// `lvs`'s `devices` column looks like `/dev/sdb1(0)` or, for
/// striped/mirrored LVs, a comma-separated list of such entries. Extract
/// the bare device path of the first segment.
fn pv_device_from_devices_field(devices: &str) -> Option<&str> {
    let first = devices.split(',').next()?;
    let name = first.split('(').next()?.trim();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

#[derive(serde::Deserialize)]
struct LvsRoot {
    report: Vec<LvsReportBlock>,
}

#[derive(serde::Deserialize)]
struct LvsReportBlock {
    lv: Vec<LvsRow>,
}

#[derive(serde::Deserialize)]
struct LvsRow {
    vg_name: String,
    lv_name: String,
    #[serde(default)]
    devices: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    /// A [`CommandRunner`] that returns pre-scripted output per
    /// `(program, args)` invocation, so tests never touch real host state.
    #[derive(Default)]
    struct FakeCommandRunner {
        responses: RefCell<HashMap<(String, Vec<String>), io::Result<(i32, &'static str, &'static str)>>>,
    }

    impl FakeCommandRunner {
        fn new() -> Self {
            Self::default()
        }

        fn script(&self, program: &str, args: &[&str], exit_code: i32, stdout: &'static str, stderr: &'static str) {
            self.responses.borrow_mut().insert(
                (program.to_string(), args.iter().map(|s| s.to_string()).collect()),
                Ok((exit_code, stdout, stderr)),
            );
        }

        fn script_not_found(&self, program: &str, args: &[&str]) {
            self.responses.borrow_mut().insert(
                (program.to_string(), args.iter().map(|s| s.to_string()).collect()),
                Err(io::Error::new(io::ErrorKind::NotFound, "no such file or directory")),
            );
        }
    }

    impl CommandRunner for FakeCommandRunner {
        fn run(&self, program: &str, args: &[&str]) -> io::Result<Output> {
            let key = (program.to_string(), args.iter().map(|s| s.to_string()).collect::<Vec<_>>());
            let responses = self.responses.borrow();
            match responses.get(&key) {
                Some(Ok((code, stdout, stderr))) => Ok(Output {
                    // `ExitStatus::from_raw` takes a raw Linux `wait(2)`
                    // status word, where a normal exit encodes the exit
                    // code in the upper byte (`code << 8`), not the bare
                    // exit code itself.
                    status: ExitStatus::from_raw(code << 8),
                    stdout: stdout.as_bytes().to_vec(),
                    stderr: stderr.as_bytes().to_vec(),
                }),
                Some(Err(e)) => Err(io::Error::new(e.kind(), e.to_string())),
                None => panic!("unscripted command: {program} {args:?}"),
            }
        }
    }

    fn discoverer(runner: FakeCommandRunner) -> CliProbeDiscoverer<FakeCommandRunner> {
        CliProbeDiscoverer::with_runner(runner)
    }

    #[test]
    fn plain_device_with_filesystem() {
        let runner = FakeCommandRunner::new();
        runner.script(
            "blkid",
            &["-o", "export"],
            0,
            "DEVNAME=/dev/sda1\nTYPE=ext4\n\n",
            "",
        );
        runner.script("cryptsetup", &["isLuks", "/dev/sda1"], 1, "", "");

        let devices = discoverer(runner).discover().unwrap();
        assert_eq!(
            devices,
            vec![PassthroughDevice::new("/dev/sda1", DeviceKind::Plain)]
        );
    }

    #[test]
    fn luks_device_is_reported_without_opening_it() {
        let runner = FakeCommandRunner::new();
        runner.script(
            "blkid",
            &["-o", "export"],
            0,
            "DEVNAME=/dev/sdb2\nTYPE=crypto_LUKS\n\n",
            "",
        );
        runner.script("cryptsetup", &["isLuks", "/dev/sdb2"], 0, "", "");

        let devices = discoverer(runner).discover().unwrap();
        assert_eq!(
            devices,
            vec![PassthroughDevice::new("/dev/sdb2", DeviceKind::Luks)]
        );
    }

    #[test]
    fn lvm_member_resolves_vg_and_lv() {
        let runner = FakeCommandRunner::new();
        runner.script(
            "blkid",
            &["-o", "export"],
            0,
            "DEVNAME=/dev/sdc1\nTYPE=LVM2_member\n\n",
            "",
        );
        runner.script("cryptsetup", &["isLuks", "/dev/sdc1"], 1, "", "");
        runner.script(
            "lvs",
            &["--reportformat", "json", "-o", "vg_name,lv_name,devices"],
            0,
            r#"{"report":[{"lv":[{"vg_name":"data-vg","lv_name":"data-lv","devices":"/dev/sdc1(0)"}]}]}"#,
            "",
        );

        let devices = discoverer(runner).discover().unwrap();
        assert_eq!(
            devices,
            vec![PassthroughDevice::new(
                "/dev/sdc1",
                DeviceKind::Lvm {
                    volume_group: "data-vg".to_string(),
                    logical_volume: "data-lv".to_string(),
                }
            )]
        );
    }

    #[test]
    fn lvm_member_without_resolvable_lv_is_skipped() {
        let runner = FakeCommandRunner::new();
        runner.script(
            "blkid",
            &["-o", "export"],
            0,
            "DEVNAME=/dev/sdd1\nTYPE=LVM2_member\n\n",
            "",
        );
        runner.script("cryptsetup", &["isLuks", "/dev/sdd1"], 1, "", "");
        runner.script(
            "lvs",
            &["--reportformat", "json", "-o", "vg_name,lv_name,devices"],
            0,
            r#"{"report":[{"lv":[]}]}"#,
            "",
        );

        let devices = discoverer(runner).discover().unwrap();
        assert!(devices.is_empty());
    }

    #[test]
    fn no_eligible_device_returns_empty_result_not_error() {
        let runner = FakeCommandRunner::new();
        runner.script("blkid", &["-o", "export"], 2, "", "");

        let devices = discoverer(runner).discover().unwrap();
        assert!(devices.is_empty());
    }

    #[test]
    fn missing_tool_is_a_typed_error() {
        let runner = FakeCommandRunner::new();
        runner.script_not_found("blkid", &["-o", "export"]);

        let err = discoverer(runner).discover().unwrap_err();
        match err {
            DiscoveryError::ToolUnavailable { tool, .. } => assert_eq!(tool, "blkid"),
            other => panic!("expected ToolUnavailable, got {other:?}"),
        }
    }

    #[test]
    fn discovery_never_invokes_activation_commands() {
        // Guards the "Discovery is read-only" requirement: the fake runner
        // panics on any unscripted invocation, so if discover() ever tried
        // to call `cryptsetup open`, `vgchange`, or `mount`, this test
        // would fail with a panic rather than silently succeeding.
        let runner = FakeCommandRunner::new();
        runner.script(
            "blkid",
            &["-o", "export"],
            0,
            "DEVNAME=/dev/sdb2\nTYPE=crypto_LUKS\n\n",
            "",
        );
        runner.script("cryptsetup", &["isLuks", "/dev/sdb2"], 0, "", "");

        discoverer(runner).discover().unwrap();
    }
}
