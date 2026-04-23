"""OS hardening and security configuration checks."""

from pathlib import Path

from .base import BaseCheck, CheckResult
from ..utils.subprocess_safe import run_safe, SafeSubprocessError
from ..models import SeverityLevel, ConfidenceLevel, Category


class HardeningCheck(BaseCheck):
    """Check OS hardening and security configuration."""
    
    check_id = "hardening"
    check_name = "OS Hardening Indicators"
    category = Category.HARDENING
    
    # Kernel parameters to check
    SECURITY_SYSCTLS = {
        "kernel.randomize_va_space": ("2", SeverityLevel.MEDIUM),  # ASLR
        "kernel.kptr_restrict": ("2", SeverityLevel.LOW),  # Kernel pointer hide
        "kernel.dmesg_restrict": ("1", SeverityLevel.LOW),  # dmesg restriction
        "fs.protected_symlinks": ("1", SeverityLevel.MEDIUM),  # Symlink protection
        "fs.protected_hardlinks": ("1", SeverityLevel.MEDIUM),  # Hardlink protection
        "net.ipv4.conf.all.rp_filter": ("1", SeverityLevel.MEDIUM),  # Reverse path filter
        "net.ipv4.conf.default.rp_filter": ("1", SeverityLevel.MEDIUM),
        "net.ipv4.icmp_echo_ignore_broadcasts": ("1", SeverityLevel.LOW),
    }
    
    def run(self) -> CheckResult:
        """Execute hardening checks."""
        result = self._create_result()
        
        # Only run on local endpoint
        if not self.scope.local_endpoint:
            return self._finish_result(result)
        
        # Check kernel security parameters
        self._check_sysctl_security(result)
        
        # Check for automatic updates
        self._check_auto_updates(result)
        
        # Check for security logging
        self._check_security_logging(result)
        
        # Check for core dumps
        self._check_core_dumps(result)
        
        # Check SSH configuration
        if self.config.check.check_ssh_config:
            self._check_ssh_config(result)
        
        # Check for password policies
        self._check_password_policy(result)
        
        return self._finish_result(result)
    
    def _check_sysctl_security(self, result: CheckResult) -> None:
        """Check kernel security parameters via sysctl."""
        for param, (expected, severity) in self.SECURITY_SYSCTLS.items():
            try:
                sysctl_result = run_safe(
                    ["sysctl", "-n", param],
                    capture_output=True,
                )
                
                if sysctl_result.returncode == 0:
                    actual = sysctl_result.stdout.strip()
                    
                    if actual != expected:
                        finding = self._create_finding(
                            title=f"Kernel security parameter not set to recommended value",
                            severity=severity,
                            target=f"sysctl {param}",
                            evidence=f"Current: {actual}, Recommended: {expected}",
                            remediation=f"Set {param}={expected} in /etc/sysctl.conf and run sysctl -p",
                            confidence=ConfidenceLevel.CERTAIN,
                            references=["https://www.kernel.org/doc/Documentation/sysctl/"],
                            metadata={
                                "parameter": param,
                                "current_value": actual,
                                "recommended_value": expected,
                            },
                        )
                        result.findings.append(finding)
                        
            except SafeSubprocessError:
                pass
            except Exception as e:
                self._log_error(f"Error checking sysctl {param}", e)
    
    def _check_auto_updates(self, result: CheckResult) -> None:
        """Check if automatic security updates are configured."""
        # Check for unattended-upgrades (Debian/Ubuntu)
        unattended_upgrade_paths = [
            Path("/etc/apt/apt.conf.d/50unattended-upgrades"),
            Path("/etc/apt/apt.conf.d/20auto-upgrades"),
        ]
        
        has_auto_upgrade = False
        for path in unattended_upgrade_paths:
            if path.exists():
                try:
                    content = path.read_text()
                    if "Unattended-Upgrade::Allowed-Origins" in content or "APT::Periodic::Unattended-Upgrade" in content:
                        has_auto_upgrade = True
                        break
                except Exception:
                    pass
        
        # Check for dnf-automatic (RHEL/Fedora)
        dnf_automatic_path = Path("/etc/dnf/automatic.conf")
        if dnf_automatic_path.exists():
            try:
                content = dnf_automatic_path.read_text()
                if "apply_updates = yes" in content.lower():
                    has_auto_upgrade = True
            except Exception:
                pass
        
        if not has_auto_upgrade:
            finding = self._create_finding(
                title="Automatic security updates not configured",
                severity=SeverityLevel.MEDIUM,
                target="package manager",
                evidence="No unattended-upgrades or dnf-automatic configuration found",
                remediation="Configure automatic security updates (unattended-upgrades on Debian/Ubuntu, dnf-automatic on RHEL)",
                confidence=ConfidenceLevel.TENTATIVE,
                references=[
                    "https://wiki.debian.org/UnattendedUpgrades",
                    "https://fedoraproject.org/wiki/AutoUpdates",
                ],
            )
            result.findings.append(finding)
    
    def _check_security_logging(self, result: CheckResult) -> None:
        """Check if security logging is enabled."""
        # Check for auditd
        auditd_path = Path("/sbin/auditd")
        auditctl_path = Path("/sbin/auditctl")
        
        audit_installed = auditd_path.exists() or auditctl_path.exists()
        
        # Check if running
        audit_running = False
        if audit_installed:
            try:
                result_check = run_safe(
                    ["pgrep", "auditd"],
                    capture_output=True,
                )
                audit_running = result_check.returncode == 0
            except SafeSubprocessError:
                pass
        
        if not audit_running:
            # Check for alternative logging (rsyslog, journald)
            journald_path = Path("/etc/systemd/journald.conf")
            rsyslog_path = Path("/etc/rsyslog.conf")
            
            has_logging = journald_path.exists() or rsyslog_path.exists()
            
            if not has_logging:
                finding = self._create_finding(
                    title="Security logging may not be properly configured",
                    severity=SeverityLevel.MEDIUM,
                    target="logging system",
                    evidence="No auditd, journald, or rsyslog detected",
                    remediation="Install and configure auditd or ensure systemd-journald/rsyslog is active",
                    confidence=ConfidenceLevel.TENTATIVE,
                    references=["https://linux-audit.com/"],
                )
                result.findings.append(finding)
    
    def _check_core_dumps(self, result: CheckResult) -> None:
        """Check if core dumps are properly limited."""
        # Check ulimit configuration
        limits_files = [
            Path("/etc/security/limits.conf"),
            Path("/etc/security/limits.d/"),
        ]
        
        core_dump_limited = False
        
        # Check main limits file
        if limits_files[0].exists():
            try:
                content = limits_files[0].read_text()
                if "core" in content.lower() and ("0" in content or "disable" in content.lower()):
                    core_dump_limited = True
            except Exception:
                pass
        
        # Check limits.d directory
        if limits_files[1].exists() and limits_files[1].is_dir():
            try:
                for conf_file in limits_files[1].glob("*.conf"):
                    try:
                        content = conf_file.read_text()
                        if "core" in content.lower():
                            core_dump_limited = True
                            break
                    except Exception:
                        pass
            except Exception:
                pass
        
        # Check sysctl for core pattern
        try:
            sysctl_result = run_safe(
                ["sysctl", "-n", "kernel.core_pattern"],
                capture_output=True,
            )
            if sysctl_result.returncode == 0:
                core_pattern = sysctl_result.stdout.strip()
                if core_pattern in ["|/bin/false", "|/dev/null", "/dev/null"]:
                    core_dump_limited = True
        except SafeSubprocessError:
            pass
        
        if not core_dump_limited:
            finding = self._create_finding(
                title="Core dumps not properly limited",
                severity=SeverityLevel.LOW,
                target="core dump configuration",
                evidence="Core dumps may be enabled without restrictions",
                remediation="Limit core dumps: echo '* hard core 0' >> /etc/security/limits.conf",
                confidence=ConfidenceLevel.TENTATIVE,
                references=["https://linux-audit.com/software/core-dumps/"],
            )
            result.findings.append(finding)
    
    def _check_ssh_config(self, result: CheckResult) -> None:
        """Check SSH configuration for security."""
        ssh_config_paths = [
            Path("/etc/ssh/sshd_config"),
            Path("/etc/ssh/ssh_config"),
        ]
        
        for config_path in ssh_config_paths:
            if not config_path.exists():
                continue
            
            try:
                content = config_path.read_text()
                lines = content.split("\n")
                
                # Check for root login
                root_login_line = None
                password_auth_line = None
                permit_empty_passwords = None
                
                for line in lines:
                    line = line.strip()
                    if line.startswith("#"):
                        continue
                    
                    if "PermitRootLogin" in line:
                        root_login_line = line
                    if "PasswordAuthentication" in line:
                        password_auth_line = line
                    if "PermitEmptyPasswords" in line:
                        permit_empty_passwords = line
                
                # Check root login
                if root_login_line and "yes" in root_login_line.lower():
                    finding = self._create_finding(
                        title="SSH root login is permitted",
                        severity=SeverityLevel.HIGH,
                        target=str(config_path),
                        evidence=f"PermitRootLogin is enabled: {root_login_line}",
                        remediation="Disable root login: PermitRootLogin no in /etc/ssh/sshd_config",
                        confidence=ConfidenceLevel.CERTAIN,
                        references=["https://www.ssh.com/ssh/sshd_config/"],
                    )
                    result.findings.append(finding)
                
                # Check password authentication
                if password_auth_line and "yes" in password_auth_line.lower():
                    finding = self._create_finding(
                        title="SSH password authentication is enabled",
                        severity=SeverityLevel.MEDIUM,
                        target=str(config_path),
                        evidence=f"PasswordAuthentication is enabled: {password_auth_line}",
                        remediation="Consider using key-based authentication: PasswordAuthentication no",
                        confidence=ConfidenceLevel.CERTAIN,
                        references=["https://www.ssh.com/ssh/key/"],
                    )
                    result.findings.append(finding)
                
                # Check empty passwords
                if permit_empty_passwords and "yes" in permit_empty_passwords.lower():
                    finding = self._create_finding(
                        title="SSH empty passwords are permitted",
                        severity=SeverityLevel.CRITICAL,
                        target=str(config_path),
                        evidence=f"PermitEmptyPasswords is enabled: {permit_empty_passwords}",
                        remediation="Disable empty passwords: PermitEmptyPasswords no",
                        confidence=ConfidenceLevel.CERTAIN,
                        references=["https://www.ssh.com/ssh/sshd_config/"],
                    )
                    result.findings.append(finding)
                    
            except Exception as e:
                self._log_error(f"Error reading SSH config {config_path}", e)
    
    def _check_password_policy(self, result: CheckResult) -> None:
        """Check for password policy configuration."""
        # Check for pam_pwquality or pam_cracklib
        pam_files = [
            Path("/etc/pam.d/common-password"),
            Path("/etc/pam.d/system-auth"),
            Path("/etc/pam.d/password-auth"),
        ]
        
        has_password_policy = False
        
        for pam_file in pam_files:
            if pam_file.exists():
                try:
                    content = pam_file.read_text()
                    if "pam_pwquality" in content or "pam_cracklib" in content:
                        has_password_policy = True
                        break
                except Exception:
                    pass
        
        if not has_password_policy:
            finding = self._create_finding(
                title="Password quality policy may not be enforced",
                severity=SeverityLevel.LOW,
                target="PAM configuration",
                evidence="No pam_pwquality or pam_cracklib found in PAM configuration",
                remediation="Configure password quality requirements in /etc/security/pwquality.conf",
                confidence=ConfidenceLevel.TENTATIVE,
                references=["https://wiki.debian.org/PasswordQuality"],
            )
            result.findings.append(finding)
    
    @classmethod
    def get_description(cls) -> str:
        return """
        Checks OS hardening indicators:
        - Kernel security parameters (ASLR, pointer hiding, symlink protection)
        - Automatic security update configuration
        - Security logging (auditd, journald)
        - Core dump restrictions
        - SSH security configuration
        - Password policy enforcement
        """
    
    @classmethod
    def get_requirements(cls) -> list[str]:
        return [
            "Read access to /proc/sys",
            "Read access to SSH configuration",
            "Read access to PAM configuration",
        ]
