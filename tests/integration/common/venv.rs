//! Python virtual environment management for integration tests.
//!
//! Handles creation and validation of a Python virtual environment
//! with the RNS package installed for testing against the reference
//! implementation.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// Global singleton for the Python venv.
static VENV: OnceLock<Result<PythonVenv, String>> = OnceLock::new();

/// Error type for venv operations.
#[derive(Debug, Clone)]
pub struct VenvError(pub String);

impl std::fmt::Display for VenvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VenvError: {}", self.0)
    }
}

impl std::error::Error for VenvError {}

impl From<io::Error> for VenvError {
    fn from(err: io::Error) -> Self {
        VenvError(err.to_string())
    }
}

/// A managed Python virtual environment for integration tests.
#[derive(Debug, Clone)]
pub struct PythonVenv {
    /// Path to the venv directory.
    venv_path: PathBuf,
    /// Path to the Python executable in the venv.
    python_bin: PathBuf,
    /// Path to pip in the venv.
    pip_bin: PathBuf,
}

impl PythonVenv {
    /// Get or create the shared venv for integration tests.
    ///
    /// This function is thread-safe and will only create the venv once,
    /// even when called from multiple test threads concurrently.
    pub fn get_or_create() -> Result<&'static PythonVenv, VenvError> {
        VENV.get_or_init(|| Self::setup().map_err(|e| e.0.clone()))
            .as_ref()
            .map_err(|e| VenvError(e.clone()))
    }

    /// Set up the Python venv.
    fn setup() -> Result<PythonVenv, VenvError> {
        let integration_dir = Self::integration_test_dir()?;
        let venv_path = integration_dir.join(".venv");
        let requirements_path = integration_dir.join("fixtures").join("requirements.txt");

        // Determine Python and pip paths based on platform
        let (python_bin, pip_bin) = if cfg!(windows) {
            (
                venv_path.join("Scripts").join("python.exe"),
                venv_path.join("Scripts").join("pip.exe"),
            )
        } else {
            (
                venv_path.join("bin").join("python"),
                venv_path.join("bin").join("pip"),
            )
        };

        let venv = PythonVenv {
            venv_path: venv_path.clone(),
            python_bin,
            pip_bin,
        };

        // Check if venv already exists and is valid
        if venv_path.exists() {
            if let Ok(()) = venv.validate() {
                eprintln!("[integration-test] Using existing Python venv at {:?}", venv_path);
                return Ok(venv);
            }
            // Invalid venv, remove and recreate
            eprintln!("[integration-test] Existing venv is invalid, recreating...");
            fs::remove_dir_all(&venv_path)?;
        }

        // Create the venv
        eprintln!("[integration-test] Creating Python venv at {:?}", venv_path);
        venv.create_venv()?;

        // Install requirements
        eprintln!("[integration-test] Installing requirements from {:?}", requirements_path);
        venv.install_requirements(&requirements_path)?;

        // Validate the installation
        venv.validate()?;

        eprintln!("[integration-test] Python venv ready");
        Ok(venv)
    }

    /// Get the path to the integration test directory.
    fn integration_test_dir() -> Result<PathBuf, VenvError> {
        // Start from CARGO_MANIFEST_DIR and navigate to tests/integration
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
            .map_err(|_| VenvError("CARGO_MANIFEST_DIR not set".to_string()))?;
        let path = PathBuf::from(manifest_dir).join("tests").join("integration");

        if !path.exists() {
            return Err(VenvError(format!(
                "Integration test directory not found: {:?}",
                path
            )));
        }

        Ok(path)
    }

    /// Create the Python virtual environment.
    fn create_venv(&self) -> Result<(), VenvError> {
        let output = Command::new("python3")
            .args(["-m", "venv", self.venv_path.to_str().unwrap()])
            .output()?;

        if !output.status.success() {
            return Err(VenvError(format!(
                "Failed to create venv: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(())
    }

    /// Install requirements from requirements.txt.
    fn install_requirements(&self, requirements_path: &Path) -> Result<(), VenvError> {
        if !requirements_path.exists() {
            return Err(VenvError(format!(
                "requirements.txt not found: {:?}",
                requirements_path
            )));
        }

        let output = Command::new(&self.pip_bin)
            .args([
                "install",
                "-r",
                requirements_path.to_str().unwrap(),
                "--quiet",
            ])
            .output()?;

        if !output.status.success() {
            return Err(VenvError(format!(
                "Failed to install requirements: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(())
    }

    /// Validate that the venv is properly set up.
    fn validate(&self) -> Result<(), VenvError> {
        // Check that Python executable exists
        if !self.python_bin.exists() {
            return Err(VenvError(format!(
                "Python binary not found: {:?}",
                self.python_bin
            )));
        }

        // Check that RNS can be imported
        let output = Command::new(&self.python_bin)
            .args(["-c", "import RNS; print(RNS.__version__)"])
            .output()?;

        if !output.status.success() {
            return Err(VenvError(format!(
                "RNS import failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
        eprintln!("[integration-test] RNS version: {}", version);

        Ok(())
    }

    /// Get the path to the Python executable in the venv.
    pub fn python(&self) -> &Path {
        &self.python_bin
    }

    /// Get the path to the venv directory.
    pub fn venv_path(&self) -> &Path {
        &self.venv_path
    }

    /// Create a Command configured to run Python with this venv.
    pub fn python_command(&self) -> Command {
        Command::new(&self.python_bin)
    }

    /// Run a Python module (e.g., `RNS.Utilities.rnsd`).
    pub fn run_module(&self, module: &str) -> Command {
        let mut cmd = Command::new(&self.python_bin);
        cmd.args(["-m", module]);
        cmd
    }

    /// Run rnsd daemon with the given arguments.
    pub fn rnsd(&self) -> Command {
        self.run_module("RNS.Utilities.rnsd")
    }

    /// Run rnstatus with the given arguments.
    pub fn rnstatus(&self) -> Command {
        self.run_module("RNS.Utilities.rnstatus")
    }

    /// Run rnpath with the given arguments.
    pub fn rnpath(&self) -> Command {
        self.run_module("RNS.Utilities.rnpath")
    }

    /// Run rnprobe with the given arguments.
    pub fn rnprobe(&self) -> Command {
        self.run_module("RNS.Utilities.rnprobe")
    }

    /// Run rnid with the given arguments.
    pub fn rnid(&self) -> Command {
        self.run_module("RNS.Utilities.rnid")
    }

    /// Run a Python helper script from the helpers directory.
    pub fn run_helper(&self, script_name: &str) -> Result<Command, VenvError> {
        let integration_dir = Self::integration_test_dir()?;
        let script_path = integration_dir.join("helpers").join(script_name);

        if !script_path.exists() {
            return Err(VenvError(format!(
                "Helper script not found: {:?}",
                script_path
            )));
        }

        let mut cmd = Command::new(&self.python_bin);
        cmd.arg(&script_path);
        Ok(cmd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integration_test_dir_exists() {
        let dir = PythonVenv::integration_test_dir().unwrap();
        assert!(dir.exists());
        assert!(dir.join("fixtures").join("requirements.txt").exists());
    }
}
