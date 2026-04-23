"""Compliance framework mappings and CIS benchmark references."""

from dataclasses import dataclass
from typing import Optional
from enum import Enum


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""
    CIS = "cis"
    NIST_800_53 = "nist_800_53"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    SOC2 = "soc2"
    ISO27001 = "iso27001"


@dataclass
class CISControl:
    """CIS Control reference."""
    control_id: str
    title: str
    section: str
    level: int  # 1 or 2
    
    def __str__(self) -> str:
        return f"CIS {self.section}.{self.control_id}: {self.title}"


@dataclass
class NISTControl:
    """NIST 800-53 control reference."""
    control_id: str
    title: str
    family: str
    impact: str  # low, moderate, high
    
    def __str__(self) -> str:
        return f"NIST 800-53 {self.control_id} ({self.family}): {self.title}"


class CISMapping:
    """CIS Benchmark mappings for security checks."""
    
    # CIS Controls v8 mappings
    CONTROLS = {
        # Inventory and Control of Enterprise Assets
        "1.1": CISControl("1.1", "Establish and Maintain Detailed Enterprise Asset Inventory", "1", 1),
        "1.2": CISControl("1.2", "Address Unauthorized Assets", "1", 1),
        
        # Inventory and Control of Software Assets
        "2.1": CISControl("2.1", "Establish and Maintain a Software Inventory", "2", 1),
        "2.2": CISControl("2.2", "Ensure Authorized Software is Currently Supported", "2", 1),
        
        # Data Protection
        "3.1": CISControl("3.1", "Establish and Maintain a Data Management Process", "3", 1),
        "3.2": CISControl("3.2", "Establish and Maintain a Data Inventory", "3", 1),
        
        # Secure Configuration of Enterprise Assets and Software
        "4.1": CISControl("4.1", "Establish and Maintain a Secure Configuration Process", "4", 1),
        "4.2": CISControl("4.2", "Establish and Maintain a Secure Configuration Process for Network Infrastructure", "4", 1),
        
        # Account Management
        "5.1": CISControl("5.1", "Establish and Maintain an Inventory of Accounts", "5", 1),
        "5.2": CISControl("5.2", "Use Unique Passwords", "5", 1),
        "5.4": CISControl("5.4", "Restrict Administrator Privileges to Dedicated Accounts", "5", 1),
        
        # Access Control Management
        "6.1": CISControl("6.1", "Establish an Access Granting Process", "6", 1),
        "6.2": CISControl("6.2", "Establish an Access Revoking Process", "6", 1),
        "6.3": CISControl("6.3", "Require MFA for Externally-Exposed Applications", "6", 1),
        "6.5": CISControl("6.5", "Require MFA for Administrative Access", "6", 1),
        
        # Continuous Vulnerability Management
        "7.1": CISControl("7.1", "Establish and Maintain a Vulnerability Management Process", "7", 1),
        "7.2": CISControl("7.2", "Establish and Maintain a Remediation Process", "7", 1),
        
        # Audit Log Management
        "8.1": CISControl("8.1", "Establish and Maintain an Audit Log Management Process", "8", 1),
        "8.2": CISControl("8.2", "Collect Audit Logs", "8", 1),
        "8.3": CISControl("8.3", "Ensure Adequate Audit Log Storage", "8", 1),
        
        # Email and Web Browser Protections
        "9.1": CISControl("9.1", "Ensure Use of Only Fully Supported Browsers and Email Clients", "9", 1),
        
        # Malware Defenses
        "10.1": CISControl("10.1", "Deploy and Maintain Anti-Malware Software", "10", 1),
        "10.2": CISControl("10.2", "Configure Automatic Anti-Malware Signature Updates", "10", 1),
        
        # Data Recovery
        "11.1": CISControl("11.1", "Establish and Maintain a Data Recovery Process", "11", 1),
        
        # Network Infrastructure Management
        "12.1": CISControl("12.1", "Ensure Network Infrastructure is Up-to-Date", "12", 1),
        "12.2": CISControl("12.2", "Establish and Maintain a Secure Network Architecture", "12", 1),
        
        # Network Monitoring and Defense
        "13.1": CISControl("13.1", "Centralize Security Event Alerting", "13", 1),
        "13.2": CISControl("13.2", "Deploy a Host-Based Intrusion Detection Solution", "13", 2),
        
        # Security Awareness and Skills Training
        "14.1": CISControl("14.1", "Establish and Maintain a Security Awareness Program", "14", 1),
        
        # Service Provider Management
        "15.1": CISControl("15.1", "Establish and Maintain a Service Provider Management Policy", "15", 1),
        
        # Application Software Security
        "16.1": CISControl("16.1", "Establish and Maintain a Secure Application Development Process", "16", 1),
        "16.2": CISControl("16.2", "Establish and Maintain a Process to Accept and Address Software Vulnerabilities", "16", 1),
        "16.4": CISControl("16.4", "Establish and Manage an Inventory of Third-Party Software Components", "16", 1),
        "16.5": CISControl("16.5", "Use Up-to-Date and Trusted Third-Party Software Components", "16", 1),
        
        # Incident Response Management
        "17.1": CISControl("17.1", "Establish and Maintain an Enterprise Process for Reporting Incidents", "17", 1),
        
        # Penetration Testing (defensive only for this tool)
        "18.1": CISControl("18.1", "Establish and Maintain a Penetration Testing Program", "18", 2),
    }
    
    # CIS Benchmarks for specific platforms
    BENCHMARKS = {
        "ubuntu": "CIS Ubuntu Linux Benchmark",
        "rhel": "CIS Red Hat Enterprise Linux Benchmark",
        "centos": "CIS CentOS Linux Benchmark",
        "debian": "CIS Debian Linux Benchmark",
        "docker": "CIS Docker Benchmark",
        "k8s": "CIS Kubernetes Benchmark",
        "aws": "CIS Amazon Web Services Foundations Benchmark",
        "azure": "CIS Microsoft Azure Foundations Benchmark",
    }
    
    @classmethod
    def get_control(cls, control_id: str) -> Optional[CISControl]:
        """Get CIS control by ID."""
        return cls.CONTROLS.get(control_id)
    
    @classmethod
    def get_recommendations_for_category(cls, category: str) -> list[CISControl]:
        """Get relevant CIS controls for a check category."""
        category_mappings = {
            "permissions": ["5.4", "6.1", "6.2"],
            "services": ["4.1", "4.2", "12.1"],
            "firewall": ["12.2", "13.1", "13.2"],
            "hardening": ["4.1", "4.2", "10.1", "10.2"],
            "secrets": ["3.1", "3.2", "5.2"],
            "dependencies": ["2.1", "2.2", "16.4", "16.5"],
            "tls": ["9.1", "12.2"],
            "containers": ["4.1", "12.2", "16.1"],
            "webapp_config": ["4.1", "16.1", "16.2"],
        }
        
        control_ids = category_mappings.get(category, [])
        return [cls.CONTROLS[cid] for cid in control_ids if cid in cls.CONTROLS]
    
    @classmethod
    def get_benchmark_for_platform(cls, platform: str) -> Optional[str]:
        """Get appropriate CIS benchmark for a platform."""
        platform = platform.lower()
        for key, benchmark in cls.BENCHMARKS.items():
            if key in platform:
                return benchmark
        return None


class ComplianceMapper:
    """Maps findings to various compliance frameworks."""
    
    # PCI DSS v4.0 requirements
    PCI_REQUIREMENTS = {
        "1.1": "Install and maintain a firewall configuration",
        "2.1": "Change vendor-supplied defaults",
        "3.1": "Keep stored PAN data to a minimum",
        "4.1": "Use strong cryptography for transmission",
        "6.1": "Establish processes for security patches",
        "6.2": "Ensure software security patches installed",
        "6.3": "Software security patches installed within one month",
        "6.4": "Critical security patches installed within one month",
        "6.5": "Address common coding vulnerabilities",
        "7.1": "Limit access to system components",
        "8.1": "Define and implement password policies",
        "8.2": "Use strong authentication",
        "10.1": "Implement audit trails",
        "11.1": "Implement security testing processes",
    }
    
    # HIPAA Security Rule mappings (simplified)
    HIPAA_CONTROLS = {
        "164.308(a)(1)": "Security Management Process",
        "164.308(a)(3)": "Workforce Security",
        "164.308(a)(4)": "Information Access Management",
        "164.308(a)(5)": "Security Awareness and Training",
        "164.308(a)(6)": "Security Incident Procedures",
        "164.312(a)(1)": "Access Control",
        "164.312(a)(2)(iv)": "Encryption and Decryption",
        "164.312(b)": "Audit Controls",
        "164.312(c)(1)": "Integrity",
        "164.312(d)": "Person or Entity Authentication",
        "164.312(e)(1)": "Transmission Security",
    }
    
    @classmethod
    def get_pci_requirement(cls, req_id: str) -> Optional[str]:
        """Get PCI DSS requirement description."""
        return cls.PCI_REQUIREMENTS.get(req_id)
    
    @classmethod
    def get_hipaa_control(cls, control_id: str) -> Optional[str]:
        """Get HIPAA control description."""
        return cls.HIPAA_CONTROLS.get(control_id)
    
    @classmethod
    def map_finding_to_pci(
        cls, 
        category: str, 
        description: str
    ) -> list[str]:
        """Map a finding to relevant PCI DSS requirements."""
        pci_mappings = {
            "firewall": ["1.1"],
            "permissions": ["7.1", "8.1"],
            "secrets": ["3.1", "8.2"],
            "tls": ["4.1"],
            "dependencies": ["6.1", "6.2", "6.3", "6.4"],
            "webapp_config": ["6.5"],
            "hardening": ["2.1"],
            "services": ["1.1", "2.1"],
        }
        return pci_mappings.get(category, [])
    
    @classmethod
    def map_finding_to_hipaa(
        cls, 
        category: str
    ) -> list[str]:
        """Map a finding to relevant HIPAA controls."""
        hipaa_mappings = {
            "permissions": ["164.308(a)(4)", "164.312(a)(1)"],
            "secrets": ["164.312(d)", "164.312(a)(2)(iv)"],
            "tls": ["164.312(e)(1)"],
            "hardening": ["164.308(a)(1)"],
            "services": ["164.308(a)(1)"],
            "firewall": ["164.312(e)(1)"],
            "audit": ["164.312(b)"],
        }
        return hipaa_mappings.get(category, [])
