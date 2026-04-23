"""Firewall and network security configuration checks."""

from pathlib import Path

from .base import BaseCheck, CheckResult
from ..utils.subprocess_safe import run_safe, SafeSubprocessError
from ..models import SeverityLevel, ConfidenceLevel, Category


class FirewallCheck(BaseCheck):
    """Check firewall status and configuration."""
    
    check_id = "firewall"
    check_name = "Firewall Status and Configuration"
    category = Category.FIREWALL
    
    def run(self) -> CheckResult:
        """Execute firewall checks."""
        result = self._create_result()
        
        # Only run on local endpoint
        if not self.scope.local_endpoint:
            return self._finish_result(result)
        
        # Check iptables
        self._check_iptables(result)
        
        # Check firewalld
        self._check_firewalld(result)
        
        # Check UFW
        self._check_ufw(result)
        
        # Check for default-deny policy
        self._check_default_policy(result)
        
        return self._finish_result(result)
    
    def _check_iptables(self, result: CheckResult) -> None:
        """Check iptables rules."""
        iptables_paths = ["/usr/sbin/iptables", "/sbin/iptables"]
        iptables_found = any(Path(p).exists() for p in iptables_paths)
        
        if not iptables_found:
            return
        
        try:
            # Check if iptables is active
            result_check = run_safe(
                ["iptables", "-L", "-n"],
                capture_output=True,
            )
            
            if result_check.returncode != 0:
                finding = self._create_finding(
                    title="iptables rules cannot be read",
                    severity=SeverityLevel.MEDIUM,
                    target="iptables",
                    evidence="iptables -L command failed - may not be running",
                    remediation="Ensure iptables service is running and accessible",
                    confidence=ConfidenceLevel.MEDIUM,
                )
                result.findings.append(finding)
                return
            
            rules = result_check.stdout
            
            # Check for empty ruleset
            lines = [l.strip() for l in rules.split("\n") if l.strip()]
            
            # Count non-header lines
            rule_lines = [l for l in lines if not l.startswith("Chain") and not l.startswith("target")]
            
            if len(rule_lines) < 3:  # Empty or minimal rules
                finding = self._create_finding(
                    title="Firewall appears to have minimal or no rules configured",
                    severity=SeverityLevel.HIGH,
                    target="iptables",
                    evidence="iptables ruleset appears empty or minimal",
                    remediation="Configure iptables rules to restrict incoming traffic; implement default-deny policy",
                    confidence=ConfidenceLevel.MEDIUM,
                    references=["https://wiki.debian.org/iptables"],
                )
                result.findings.append(finding)
            
            # Check for default-deny policy on INPUT chain
            if "Chain INPUT (policy DROP)" not in rules and "Chain INPUT (policy REJECT)" not in rules:
                finding = self._create_finding(
                    title="iptables INPUT chain does not have default-deny policy",
                    severity=SeverityLevel.MEDIUM,
                    target="iptables INPUT chain",
                    evidence="INPUT chain policy is ACCEPT or not set to DROP/REJECT",
                    remediation="Set default policy to DROP: iptables -P INPUT DROP",
                    confidence=ConfidenceLevel.MEDIUM,
                    references=["https://www.cyberciti.biz/tips/linux-iptables-4-firewall.html"],
                )
                result.findings.append(finding)
            
            # Check for ESTABLISHED,RELATED rule
            if "ESTABLISHED" not in rules:
                finding = self._create_finding(
                    title="iptables may be missing established connection tracking",
                    severity=SeverityLevel.LOW,
                    target="iptables",
                    evidence="No ESTABLISHED,RELATED rule detected in iptables",
                    remediation="Add connection tracking rule: iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
                    confidence=ConfidenceLevel.TENTATIVE,
                )
                result.findings.append(finding)
                
        except SafeSubprocessError:
            pass
        except Exception as e:
            self._log_error("Error checking iptables", e)
    
    def _check_firewalld(self, result: CheckResult) -> None:
        """Check firewalld status (RHEL/CentOS/Fedora)."""
        try:
            result_check = run_safe(
                ["firewall-cmd", "--state"],
                capture_output=True,
            )
            
            if result_check.returncode != 0:
                # firewalld not running or not installed
                return
            
            # firewalld is running - get active zones
            zones_result = run_safe(
                ["firewall-cmd", "--get-active-zones"],
                capture_output=True,
            )
            
            if zones_result.returncode == 0:
                zones = zones_result.stdout.strip()
                
                # Check default zone
                default_result = run_safe(
                    ["firewall-cmd", "--get-default-zone"],
                    capture_output=True,
                )
                
                if default_result.returncode == 0:
                    default_zone = default_result.stdout.strip()
                    
                    if default_zone == "trusted":
                        finding = self._create_finding(
                            title="firewalld default zone is 'trusted' - no restrictions",
                            severity=SeverityLevel.HIGH,
                            target="firewalld",
                            evidence=f"Default zone: {default_zone}",
                            remediation="Change default zone to 'public' or 'drop': firewall-cmd --set-default-zone=public",
                            confidence=ConfidenceLevel.CERTAIN,
                            references=["https://firewalld.org/documentation/"],
                        )
                        result.findings.append(finding)
                        
        except SafeSubprocessError:
            pass
        except Exception as e:
            self._log_error("Error checking firewalld", e)
    
    def _check_ufw(self, result: CheckResult) -> None:
        """Check UFW status (Ubuntu)."""
        ufw_path = Path("/usr/sbin/ufw")
        if not ufw_path.exists():
            return
        
        try:
            result_check = run_safe(
                ["ufw", "status", "verbose"],
                capture_output=True,
            )
            
            status_output = result_check.stdout.lower()
            
            if "status: inactive" in status_output:
                finding = self._create_finding(
                    title="UFW firewall is not active",
                    severity=SeverityLevel.HIGH,
                    target="ufw",
                    evidence="UFW status shows 'inactive'",
                    remediation="Enable UFW: sudo ufw enable",
                    confidence=ConfidenceLevel.CERTAIN,
                    references=["https://help.ubuntu.com/community/UFW"],
                )
                result.findings.append(finding)
            
            elif "status: active" in status_output:
                # Check for default deny policies
                if "deny (incoming)" not in status_output:
                    finding = self._create_finding(
                        title="UFW does not have default deny for incoming traffic",
                        severity=SeverityLevel.MEDIUM,
                        target="ufw",
                        evidence="No 'deny (incoming)' policy detected",
                        remediation="Set default deny: sudo ufw default deny incoming",
                        confidence=ConfidenceLevel.MEDIUM,
                        references=["https://help.ubuntu.com/community/UFW"],
                    )
                    result.findings.append(finding)
                    
        except SafeSubprocessError:
            pass
        except Exception as e:
            self._log_error("Error checking UFW", e)
    
    def _check_default_policy(self, result: CheckResult) -> None:
        """Check for overall default-deny security posture."""
        # Check if any firewall is active
        firewalls_checked = []
        
        try:
            run_safe(["iptables", "-L", "-n"], capture_output=True)
            firewalls_checked.append("iptables")
        except SafeSubprocessError:
            pass
        
        try:
            status = run_safe(["ufw", "status"], capture_output=True)
            if "active" in status.stdout.lower():
                firewalls_checked.append("ufw")
        except SafeSubprocessError:
            pass
        
        try:
            status = run_safe(["firewall-cmd", "--state"], capture_output=True)
            if status.returncode == 0:
                firewalls_checked.append("firewalld")
        except SafeSubprocessError:
            pass
        
        # If no firewalls detected active
        if not firewalls_checked:
            finding = self._create_finding(
                title="No active firewall detected",
                severity=SeverityLevel.HIGH,
                target="system firewall",
                evidence="No iptables, ufw, or firewalld detected as active",
                remediation="Install and configure a firewall (iptables, ufw, or firewalld)",
                confidence=ConfidenceLevel.MEDIUM,
                references=[
                    "https://wiki.debian.org/iptables",
                    "https://help.ubuntu.com/community/UFW",
                ],
            )
            result.findings.append(finding)
    
    @classmethod
    def get_description(cls) -> str:
        return """
        Checks firewall configuration and status:
        - Verifies iptables/firewalld/ufw is active
        - Checks for default-deny policies
        - Identifies missing established connection tracking
        - Flags trusted/public zone misconfigurations
        """
    
    @classmethod
    def get_requirements(cls) -> list[str]:
        return [
            "Read access to iptables (or sudo)",
            "firewall-cmd for RHEL/CentOS systems",
            "ufw for Ubuntu/Debian systems",
        ]
