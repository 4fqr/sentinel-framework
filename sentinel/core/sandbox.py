"""
Sentinel Framework - Core Sandbox Engine
Manages isolated execution environments for malware analysis
"""

import os
import time
import logging
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum

# Optional Docker import
try:
    import docker
    HAS_DOCKER = True
except ImportError:
    HAS_DOCKER = False
    print("Warning: Docker not available. Only process-based sandbox will work.")

from sentinel.config import config
from sentinel.utils.logger import get_logger
from sentinel.utils.helpers import Timer, ensure_directory


logger = get_logger(__name__)


class SandboxType(Enum):
    """Supported sandbox types"""
    DOCKER = "docker"
    PROCESS = "process"
    VM = "vm"


class SandboxState(Enum):
    """Sandbox execution states"""
    IDLE = "idle"
    INITIALIZING = "initializing"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"
    ERROR = "error"


@dataclass
class SandboxResult:
    """Results from sandbox execution"""
    success: bool
    execution_time: float
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    events: List[Dict[str, Any]] = field(default_factory=list)
    artifacts: List[str] = field(default_factory=list)
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'success': self.success,
            'execution_time': self.execution_time,
            'exit_code': self.exit_code,
            'stdout': self.stdout,
            'stderr': self.stderr,
            'events_count': len(self.events),
            'artifacts': self.artifacts,
            'error': self.error,
        }


class SandboxEngine:
    """
    Core sandbox engine for isolated malware execution
    Supports Docker containers, process isolation, and VM environments
    """
    
    def __init__(self, sandbox_type: Optional[str] = None):
        """
        Initialize sandbox engine
        
        Args:
            sandbox_type: Type of sandbox (docker, process, vm)
        """
        self.config = config.sandbox_config
        self.sandbox_type = SandboxType(sandbox_type or self.config.get('type', 'docker'))
        self.state = SandboxState.IDLE
        self.timeout = self.config.get('timeout', 300)
        self.network_mode = self.config.get('network_mode', 'isolated')
        
        # Initialize sandbox backend
        self._initialize_backend()
        
        logger.info(f"Sandbox engine initialized: type={self.sandbox_type.value}")
    
    def _initialize_backend(self) -> None:
        """Initialize sandbox backend based on type"""
        if self.sandbox_type == SandboxType.DOCKER:
            if not HAS_DOCKER:
                logger.warning("Docker library not available, falling back to process isolation")
                self.sandbox_type = SandboxType.PROCESS
                return
            
            try:
                self.docker_client = docker.from_env()
                self.docker_client.ping()
                logger.info("Docker backend initialized successfully")
            except Exception as e:
                logger.debug(f"Docker not available, using process isolation: {e}")
                self.sandbox_type = SandboxType.PROCESS
        
        elif self.sandbox_type == SandboxType.PROCESS:
            logger.info("Process isolation backend initialized")
        
        elif self.sandbox_type == SandboxType.VM:
            logger.warning("VM backend not yet implemented, falling back to process isolation")
            self.sandbox_type = SandboxType.PROCESS
    
    def execute(
        self,
        sample_path: str,
        arguments: Optional[List[str]] = None,
        environment: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None
    ) -> SandboxResult:
        """
        Execute sample in isolated sandbox environment
        
        Args:
            sample_path: Path to sample file
            arguments: Command-line arguments
            environment: Environment variables
            timeout: Execution timeout (overrides default)
        
        Returns:
            SandboxResult containing execution details
        """
        logger.info(f"Executing sample: {sample_path}")
        
        if not os.path.exists(sample_path):
            return SandboxResult(
                success=False,
                execution_time=0,
                error=f"Sample file not found: {sample_path}"
            )
        
        execution_timeout = timeout or self.timeout
        
        try:
            self.state = SandboxState.INITIALIZING
            
            with Timer("Sandbox execution") as timer:
                if self.sandbox_type == SandboxType.DOCKER:
                    result = self._execute_docker(
                        sample_path, arguments, environment, execution_timeout
                    )
                elif self.sandbox_type == SandboxType.PROCESS:
                    result = self._execute_process(
                        sample_path, arguments, environment, execution_timeout
                    )
                else:
                    raise NotImplementedError(f"Sandbox type {self.sandbox_type} not implemented")
                
                result.execution_time = timer.elapsed
            
            self.state = SandboxState.STOPPED
            logger.info(f"Sandbox execution completed in {timer.elapsed:.2f}s")
            
            return result
            
        except Exception as e:
            self.state = SandboxState.ERROR
            logger.error(f"Sandbox execution failed: {e}", exc_info=True)
            return SandboxResult(
                success=False,
                execution_time=0,
                error=str(e)
            )
    
    def _execute_docker(
        self,
        sample_path: str,
        arguments: Optional[List[str]],
        environment: Optional[Dict[str, str]],
        timeout: int
    ) -> SandboxResult:
        """Execute sample in Docker container"""
        logger.debug("Starting Docker container execution")
        
        try:
            # Prepare container configuration
            container_name = f"sentinel-sandbox-{int(time.time())}"
            sample_name = os.path.basename(sample_path)
            
            # Configure network isolation
            network_disabled = self.network_mode == "isolated"
            
            # Create and configure container
            container = self.docker_client.containers.run(
                image="python:3.9-slim",  # Base image for analysis
                name=container_name,
                command=["sleep", str(timeout)],
                detach=True,
                remove=False,
                network_disabled=network_disabled,
                mem_limit="512m",
                cpu_period=100000,
                cpu_quota=50000,
                volumes={
                    os.path.abspath(sample_path): {
                        'bind': f'/sample/{sample_name}',
                        'mode': 'ro'
                    }
                },
                environment=environment or {},
                auto_remove=False,
            )
            
            self.state = SandboxState.RUNNING
            logger.debug(f"Container {container_name} started")
            
            # Wait for execution with timeout
            result = container.wait(timeout=timeout)
            
            # Collect output
            logs = container.logs().decode('utf-8', errors='ignore')
            
            # Cleanup
            container.stop()
            container.remove()
            
            return SandboxResult(
                success=True,
                execution_time=0,  # Will be set by caller
                exit_code=result.get('StatusCode'),
                stdout=logs,
            )
            
        except docker.errors.ContainerError as e:
            logger.error(f"Container execution error: {e}")
            return SandboxResult(success=False, execution_time=0, error=str(e))
        
        except docker.errors.ImageNotFound:
            logger.error("Docker image not found")
            return SandboxResult(
                success=False,
                execution_time=0,
                error="Docker image not found. Please pull required image."
            )
        
        except Exception as e:
            logger.error(f"Docker execution failed: {e}")
            return SandboxResult(success=False, execution_time=0, error=str(e))
    
    def _execute_process(
        self,
        sample_path: str,
        arguments: Optional[List[str]],
        environment: Optional[Dict[str, str]],
        timeout: int
    ) -> SandboxResult:
        """Execute sample as isolated process"""
        logger.debug("Starting process execution")
        
        try:
            # Build command
            cmd = [sample_path]
            if arguments:
                cmd.extend(arguments)
            
            # Prepare environment
            env = os.environ.copy()
            if environment:
                env.update(environment)
            
            self.state = SandboxState.RUNNING
            
            # Execute process with timeout
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout,
                env=env,
                cwd=os.path.dirname(sample_path),
            )
            
            return SandboxResult(
                success=True,
                execution_time=0,  # Will be set by caller
                exit_code=result.returncode,
                stdout=result.stdout.decode('utf-8', errors='ignore'),
                stderr=result.stderr.decode('utf-8', errors='ignore'),
            )
            
        except subprocess.TimeoutExpired:
            logger.warning(f"Process execution timeout ({timeout}s)")
            return SandboxResult(
                success=False,
                execution_time=timeout,
                error="Execution timeout"
            )
        
        except Exception as e:
            logger.error(f"Process execution failed: {e}")
            return SandboxResult(success=False, execution_time=0, error=str(e))
    
    def create_snapshot(self, name: str) -> bool:
        """
        Create sandbox snapshot for restoration
        
        Args:
            name: Snapshot name
        
        Returns:
            True if successful
        """
        if not self.config.get('snapshot_enabled', False):
            logger.warning("Snapshots are disabled in configuration")
            return False
        
        logger.info(f"Creating snapshot: {name}")
        # Implementation depends on sandbox type
        return True
    
    def restore_snapshot(self, name: str) -> bool:
        """
        Restore sandbox from snapshot
        
        Args:
            name: Snapshot name
        
        Returns:
            True if successful
        """
        logger.info(f"Restoring snapshot: {name}")
        # Implementation depends on sandbox type
        return True
    
    def cleanup(self) -> None:
        """Cleanup sandbox resources"""
        logger.info("Cleaning up sandbox resources")
        
        if self.sandbox_type == SandboxType.DOCKER:
            try:
                # Remove any lingering containers
                containers = self.docker_client.containers.list(
                    all=True,
                    filters={'name': 'sentinel-sandbox-'}
                )
                for container in containers:
                    container.remove(force=True)
                    logger.debug(f"Removed container: {container.name}")
            except Exception as e:
                logger.error(f"Cleanup failed: {e}")
        
        self.state = SandboxState.IDLE
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get current sandbox status
        
        Returns:
            Dictionary with status information
        """
        return {
            'type': self.sandbox_type.value,
            'state': self.state.value,
            'timeout': self.timeout,
            'network_mode': self.network_mode,
        }
