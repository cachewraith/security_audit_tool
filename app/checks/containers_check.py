"""Container security configuration checks."""

from pathlib import Path

from .base import BaseCheck, CheckResult
from ..utils.subprocess_safe import run_safe, SafeSubprocessError
from ..models import SeverityLevel, ConfidenceLevel, Category


class ContainersCheck(BaseCheck):
    """Check container security configuration."""
    
    check_id = "containers"
    check_name = "Container Security Check"
    category = Category.CONTAINERS
    
    # Dangerous Dockerfile instructions
    DANGEROUS_INSTRUCTIONS = {
        "USER root": (
            SeverityLevel.MEDIUM,
            "Container runs as root user",
            "Use a non-root USER instruction",
        ),
        "privileged": (
            SeverityLevel.CRITICAL,
            "Container may run in privileged mode",
            "Avoid --privileged flag; use specific capabilities instead",
        ),
        "curl | bash": (
            SeverityLevel.HIGH,
            "Unsafe remote code execution pattern",
            "Download and verify files before execution",
        ),
        "wget | sh": (
            SeverityLevel.HIGH,
            "Unsafe remote code execution pattern",
            "Download and verify files before execution",
        ),
        "ADD http": (
            SeverityLevel.MEDIUM,
            "ADD instruction with remote URL",
            "Use curl/wget with verification instead of ADD for remote files",
        ),
        "secrets": (
            SeverityLevel.HIGH,
            "Potential secret in container instruction",
            "Use BuildKit secrets or runtime secrets instead",
        ),
    }
    
    # Docker security options to check
    SECURITY_OPTS = [
        "no-new-privileges",
        "seccomp",
        "apparmor",
    ]
    
    def run(self) -> CheckResult:
        """Execute container security checks."""
        result = self._create_result()
        
        # Check Dockerfile in project paths
        self._check_dockerfiles(result)
        
        # Check docker-compose files
        self._check_docker_compose(result)
        
        # Check running containers if in scope
        if self.scope.container_ids or self.scope.local_endpoint:
            self._check_running_containers(result)
        
        # Check container images if specified
        if self.scope.container_images:
            self._check_container_images(result)
        
        return self._finish_result(result)
    
    def _check_dockerfiles(self, result: CheckResult) -> None:
        """Check Dockerfiles in project paths."""
        for project_path in self.scope.project_paths:
            for dockerfile in project_path.rglob("Dockerfile*"):
                if not dockerfile.is_file():
                    continue
                
                try:
                    content = dockerfile.read_text()
                    lines = content.split("\n")
                    
                    # Check for dangerous patterns
                    for line_num, line in enumerate(lines, 1):
                        line_upper = line.upper()
                        
                        # Check for USER root
                        if "USER ROOT" in line_upper:
                            finding = self._create_finding(
                                title="Dockerfile uses root user",
                                severity=SeverityLevel.MEDIUM,
                                target=str(dockerfile),
                                evidence=f"Line {line_num}: {line.strip()}",
                                remediation="Add 'USER <non-root-user>' before CMD/ENTRYPOINT",
                                confidence=ConfidenceLevel.CERTAIN,
                                references=["https://docs.docker.com/develop/develop-images/dockerfile_best-practices/"],
                                metadata={"line": line_num},
                            )
                            result.findings.append(finding)
                        
                        # Check for ADD with remote URL
                        if line_upper.strip().startswith("ADD HTTP"):
                            finding = self._create_finding(
                                title="Dockerfile uses ADD with remote URL",
                                severity=SeverityLevel.MEDIUM,
                                target=str(dockerfile),
                                evidence=f"Line {line_num}: {line.strip()}",
                                remediation="Use RUN curl/wget with checksum verification instead",
                                confidence=ConfidenceLevel.CERTAIN,
                                references=["https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#add-or-copy"],
                                metadata={"line": line_num},
                            )
                            result.findings.append(finding)
                        
                        # Check for curl | bash patterns
                        if "CURL" in line_upper and ("| BASH" in line_upper or "| SH" in line_upper):
                            finding = self._create_finding(
                                title="Dockerfile has unsafe remote execution",
                                severity=SeverityLevel.HIGH,
                                target=str(dockerfile),
                                evidence=f"Line {line_num}: Potential pipe to shell pattern",
                                remediation="Download, verify checksum, then execute in separate steps",
                                confidence=ConfidenceLevel.HIGH,
                                references=["https://docs.docker.com/develop/develop-images/dockerfile_best-practices/"],
                                metadata={"line": line_num},
                            )
                            result.findings.append(finding)
                        
                        # Check for sudo
                        if "SUDO" in line_upper:
                            finding = self._create_finding(
                                title="Dockerfile uses sudo",
                                severity=SeverityLevel.LOW,
                                target=str(dockerfile),
                                evidence=f"Line {line_num}: {line.strip()}",
                                remediation="Remove sudo - containers should run commands as root directly",
                                confidence=ConfidenceLevel.CERTAIN,
                                references=["https://docs.docker.com/develop/develop-images/dockerfile_best-practices/"],
                                metadata={"line": line_num},
                            )
                            result.findings.append(finding)
                        
                        # Check for secrets in environment variables
                        secret_patterns = ["PASSWORD", "SECRET", "API_KEY", "TOKEN", "CREDENTIAL"]
                        for pattern in secret_patterns:
                            if pattern in line_upper and ("ENV" in line_upper or "ARG" in line_upper):
                                finding = self._create_finding(
                                    title=f"Dockerfile may contain hardcoded {pattern}",
                                    severity=SeverityLevel.HIGH,
                                    target=str(dockerfile),
                                    evidence=f"Line {line_num}: Potential secret in ENV/ARG",
                                    remediation="Use BuildKit secrets or pass secrets at runtime",
                                    confidence=ConfidenceLevel.TENTATIVE,
                                    references=["https://docs.docker.com/build/building/secrets/"],
                                    metadata={"line": line_num, "pattern": pattern},
                                )
                                result.findings.append(finding)
                                break
                                
                except Exception as e:
                    self._log_error(f"Error reading Dockerfile {dockerfile}", e)
    
    def _check_docker_compose(self, result: CheckResult) -> None:
        """Check docker-compose files for security issues."""
        for project_path in self.scope.project_paths:
            for pattern in ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"]:
                compose_file = project_path / pattern
                if not compose_file.exists():
                    continue
                
                try:
                    content = compose_file.read_text()
                    content_lower = content.lower()
                    
                    # Check for privileged mode
                    if "privileged: true" in content_lower:
                        finding = self._create_finding(
                            title="Docker Compose uses privileged mode",
                            severity=SeverityLevel.CRITICAL,
                            target=str(compose_file),
                            evidence="Container configured with privileged: true",
                            remediation="Remove privileged flag; use specific capabilities instead",
                            confidence=ConfidenceLevel.CERTAIN,
                            references=["https://docs.docker.com/compose/compose-file/compose-file-v3/"],
                        )
                        result.findings.append(finding)
                    
                    # Check for host network mode
                    if "network_mode: host" in content_lower:
                        finding = self._create_finding(
                            title="Docker Compose uses host network mode",
                            severity=SeverityLevel.MEDIUM,
                            target=str(compose_file),
                            evidence="Container uses host network mode",
                            remediation="Use port mapping instead of host network mode",
                            confidence=ConfidenceLevel.CERTAIN,
                            references=["https://docs.docker.com/compose/compose-file/compose-file-v3/"],
                        )
                        result.findings.append(finding)
                    
                    # Check for host pid namespace
                    if "pid: host" in content_lower:
                        finding = self._create_finding(
                            title="Docker Compose uses host PID namespace",
                            severity=SeverityLevel.MEDIUM,
                            target=str(compose_file),
                            evidence="Container shares host PID namespace",
                            remediation="Remove pid: host unless specifically required",
                            confidence=ConfidenceLevel.CERTAIN,
                            references=["https://docs.docker.com/compose/compose-file/compose-file-v3/"],
                        )
                        result.findings.append(finding)
                    
                    # Check for host IPC namespace
                    if "ipc: host" in content_lower:
                        finding = self._create_finding(
                            title="Docker Compose uses host IPC namespace",
                            severity=SeverityLevel.MEDIUM,
                            target=str(compose_file),
                            evidence="Container shares host IPC namespace",
                            remediation="Remove ipc: host unless specifically required",
                            confidence=ConfidenceLevel.CERTAIN,
                            references=["https://docs.docker.com/compose/compose-file/compose-file-v3/"],
                        )
                        result.findings.append(finding)

                    if "read_only: true" not in content_lower:
                        finding = self._create_finding(
                            title="Docker Compose services do not enforce read-only root filesystems",
                            severity=SeverityLevel.LOW,
                            target=str(compose_file),
                            evidence="No read_only: true setting found in the compose definition",
                            remediation="Enable read_only: true for services that do not need to write to the container filesystem.",
                            confidence=ConfidenceLevel.MEDIUM,
                            references=["https://docs.docker.com/engine/security/"],
                        )
                        result.findings.append(finding)

                    if "no-new-privileges:true" not in content_lower and "no-new-privileges=true" not in content_lower:
                        finding = self._create_finding(
                            title="Docker Compose is missing no-new-privileges hardening",
                            severity=SeverityLevel.MEDIUM,
                            target=str(compose_file),
                            evidence="No security_opt entry enabling no-new-privileges was found",
                            remediation="Add security_opt: [\"no-new-privileges:true\"] to services where supported.",
                            confidence=ConfidenceLevel.MEDIUM,
                            references=["https://docs.docker.com/engine/reference/run/#security-configuration"],
                        )
                        result.findings.append(finding)

                    if "cap_add:" in content_lower and "cap_drop:" not in content_lower:
                        finding = self._create_finding(
                            title="Docker Compose adds capabilities without an explicit drop policy",
                            severity=SeverityLevel.MEDIUM,
                            target=str(compose_file),
                            evidence="Capability additions were found without a matching cap_drop baseline",
                            remediation="Prefer cap_drop: [\"ALL\"] and add back only the minimal capabilities required.",
                            confidence=ConfidenceLevel.MEDIUM,
                            references=["https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities"],
                        )
                        result.findings.append(finding)
                    
                    # Check for bind mounts to sensitive paths
                    sensitive_mounts = ["/etc", "/root", "/var/run/docker.sock", "/proc", "/sys"]
                    for mount in sensitive_mounts:
                        if mount in content:
                            finding = self._create_finding(
                                title=f"Docker Compose binds mount to sensitive path: {mount}",
                                severity=SeverityLevel.HIGH,
                                target=str(compose_file),
                                evidence=f"Volume mounts to {mount}",
                                remediation="Avoid mounting sensitive host paths unless absolutely necessary",
                                confidence=ConfidenceLevel.HIGH,
                                references=["https://docs.docker.com/storage/bind-mounts/"],
                            )
                            result.findings.append(finding)

                    if ":latest" in content_lower:
                        finding = self._create_finding(
                            title="Docker Compose references mutable latest-tag images",
                            severity=SeverityLevel.LOW,
                            target=str(compose_file),
                            evidence="Compose file contains one or more image references using the latest tag",
                            remediation="Pin images to immutable versioned tags or digests to improve traceability and rollback safety.",
                            confidence=ConfidenceLevel.HIGH,
                            references=["https://docs.docker.com/develop/dev-best-practices/#pin-base-image-versions"],
                        )
                        result.findings.append(finding)
                            
                except Exception as e:
                    self._log_error(f"Error reading docker-compose file {compose_file}", e)
    
    def _check_running_containers(self, result: CheckResult) -> None:
        """Check security of running containers."""
        try:
            # Check if docker is available
            docker_check = run_safe(["docker", "version"], capture_output=True)
            if docker_check.returncode != 0:
                return
        except (SafeSubprocessError, FileNotFoundError):
            return
        
        # Get list of running containers
        try:
            ps_result = run_safe(
                ["docker", "ps", "--format", "{{.ID}}"],
                capture_output=True,
            )
            
            if ps_result.returncode != 0:
                return
            
            container_ids = ps_result.stdout.strip().split("\n")
            
            # Filter to only check containers in scope
            if self.scope.container_ids:
                container_ids = [
                    cid for cid in container_ids
                    if any(cid.startswith(sid) for sid in self.scope.container_ids)
                ]
            
            for cid in container_ids:
                if not cid:
                    continue
                
                try:
                    # Inspect container
                    inspect_result = run_safe(
                        ["docker", "inspect", cid],
                        capture_output=True,
                    )
                    
                    if inspect_result.returncode != 0:
                        continue
                    
                    import json
                    container_info = json.loads(inspect_result.stdout)[0]
                    
                    # Check for privileged mode
                    host_config = container_info.get("HostConfig", {})
                    
                    if host_config.get("Privileged", False):
                        finding = self._create_finding(
                            title="Running container has privileged mode enabled",
                            severity=SeverityLevel.CRITICAL,
                            target=f"container:{cid[:12]}",
                            evidence="Container is running with --privileged",
                            remediation="Stop container and recreate without --privileged",
                            confidence=ConfidenceLevel.CERTAIN,
                            references=["https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities"],
                        )
                        result.findings.append(finding)
                    
                    # Check for root user
                    config = container_info.get("Config", {})
                    user = config.get("User", "")
                    
                    if not user or user == "root":
                        finding = self._create_finding(
                            title="Running container as root user",
                            severity=SeverityLevel.MEDIUM,
                            target=f"container:{cid[:12]}",
                            evidence="Container is running as root user",
                            remediation="Update image to use USER instruction with non-root user",
                            confidence=ConfidenceLevel.CERTAIN,
                            references=["https://docs.docker.com/develop/develop-images/dockerfile_best-practices/"],
                        )
                        result.findings.append(finding)
                    
                    # Check for sensitive capabilities
                    cap_add = host_config.get("CapAdd", [])
                    dangerous_caps = ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE"]
                    
                    for cap in cap_add:
                        if cap in dangerous_caps:
                            finding = self._create_finding(
                                title=f"Container has dangerous capability: {cap}",
                                severity=SeverityLevel.HIGH,
                                target=f"container:{cid[:12]}",
                                evidence=f"Container has {cap} capability added",
                                remediation=f"Remove --cap-add={cap} unless absolutely required",
                                confidence=ConfidenceLevel.CERTAIN,
                                references=["https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities"],
                            )
                            result.findings.append(finding)

                    readonly_rootfs = host_config.get("ReadonlyRootfs", False)
                    if not readonly_rootfs:
                        finding = self._create_finding(
                            title="Running container has a writable root filesystem",
                            severity=SeverityLevel.LOW,
                            target=f"container:{cid[:12]}",
                            evidence="ReadonlyRootfs is disabled for the running container",
                            remediation="Enable a read-only root filesystem and mount only the specific writable paths required.",
                            confidence=ConfidenceLevel.HIGH,
                            references=["https://docs.docker.com/engine/security/"],
                        )
                        result.findings.append(finding)

                    security_opt = host_config.get("SecurityOpt", []) or []
                    if not any("no-new-privileges" in opt for opt in security_opt):
                        finding = self._create_finding(
                            title="Running container is missing no-new-privileges",
                            severity=SeverityLevel.MEDIUM,
                            target=f"container:{cid[:12]}",
                            evidence="Container runtime options do not include no-new-privileges",
                            remediation="Run the container with --security-opt no-new-privileges:true.",
                            confidence=ConfidenceLevel.HIGH,
                            references=["https://docs.docker.com/engine/reference/run/#security-configuration"],
                        )
                        result.findings.append(finding)

                    mounts = container_info.get("Mounts", []) or []
                    if any(mount.get("Source") == "/var/run/docker.sock" for mount in mounts):
                        finding = self._create_finding(
                            title="Running container mounts the Docker socket",
                            severity=SeverityLevel.CRITICAL,
                            target=f"container:{cid[:12]}",
                            evidence="Container bind-mounts /var/run/docker.sock from the host",
                            remediation="Remove Docker socket access or isolate it behind a narrowly scoped broker.",
                            confidence=ConfidenceLevel.CERTAIN,
                            references=["https://docs.docker.com/engine/security/protect-access/"],
                        )
                        result.findings.append(finding)

                    if host_config.get("PidMode") == "host":
                        finding = self._create_finding(
                            title="Running container shares the host PID namespace",
                            severity=SeverityLevel.MEDIUM,
                            target=f"container:{cid[:12]}",
                            evidence="PidMode is set to host",
                            remediation="Avoid host PID sharing unless the workload explicitly requires it.",
                            confidence=ConfidenceLevel.CERTAIN,
                            references=["https://docs.docker.com/engine/reference/run/#pid-settings---pid"],
                        )
                        result.findings.append(finding)

                    pids_limit = host_config.get("PidsLimit")
                    if pids_limit in (None, 0):
                        finding = self._create_finding(
                            title="Running container does not define a PID limit",
                            severity=SeverityLevel.LOW,
                            target=f"container:{cid[:12]}",
                            evidence="PidsLimit is not configured for the running container",
                            remediation="Set a sensible --pids-limit value to reduce process-fork exhaustion risk.",
                            confidence=ConfidenceLevel.MEDIUM,
                            references=["https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources"],
                        )
                        result.findings.append(finding)
                            
                except Exception as e:
                    self._log_error(f"Error inspecting container {cid}", e)
                    
        except Exception as e:
            self._log_error("Error checking running containers", e)
    
    def _check_container_images(self, result: CheckResult) -> None:
        """Check specified container images."""
        for image in self.scope.container_images:
            if ":" not in image or image.endswith(":latest"):
                result.findings.append(
                    self._create_finding(
                        title="Container image reference is not pinned to an immutable version",
                        severity=SeverityLevel.LOW,
                        target=image,
                        evidence="Image reference uses an implicit or latest tag",
                        remediation="Pin the image to a versioned tag or digest and review it against an image vulnerability scanner.",
                        confidence=ConfidenceLevel.HIGH,
                        references=[
                            "https://docs.docker.com/develop/dev-best-practices/#pin-base-image-versions",
                            "https://docs.docker.com/scout/",
                        ],
                    )
                )
    
    @classmethod
    def get_description(cls) -> str:
        return """
        Checks container security configuration:
        - Dockerfile best practices (non-root user, no secrets)
        - Docker Compose security (no privileged mode, no host namespace sharing)
        - Running container security settings and runtime hardening
        - Dangerous capabilities, writable root filesystems, and Docker socket access
        - Image pinning hygiene for container references
        """
    
    @classmethod
    def get_requirements(cls) -> list[str]:
        return [
            "Read access to Dockerfile and docker-compose files",
            "Docker CLI access (for running container checks)",
        ]
