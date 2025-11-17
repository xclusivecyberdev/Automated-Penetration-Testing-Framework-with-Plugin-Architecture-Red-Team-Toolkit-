"""
Main penetration testing framework orchestrator
"""

import asyncio
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime
import traceback

from .config import Config, Target
from .logger import Logger
from .plugin_loader import PluginLoader
from .session import SessionManager, SessionStatus
from plugins.base import PluginResult, PluginCategory


class PentestFramework:
    """Main framework orchestrator"""

    def __init__(
        self,
        config: Optional[Config] = None,
        logger: Optional[Logger] = None,
        session_name: Optional[str] = None
    ):
        self.config = config or Config()
        self.logger = logger or Logger()
        self.session_manager = SessionManager()
        self.plugin_loader = PluginLoader(config=self.config, logger=self.logger)

        # Create session
        self.session = self.session_manager.create_session(session_name)
        self.results: List[PluginResult] = []
        self.is_paused = False
        self.is_running = False

        # Setup output directory
        self.output_dir = self.config.output_dir / self.session.session_id
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.logger.info(f"Initialized framework session: {self.session.session_id}")

    def initialize(self):
        """Initialize the framework and load plugins"""
        self.logger.info("Initializing penetration testing framework...")

        # Discover and load plugins
        discovered = self.plugin_loader.discover_plugins()
        self.logger.info(f"Discovered {discovered} plugins")

        loaded = self.plugin_loader.load_all_plugins()
        self.logger.info(f"Loaded {loaded} plugins")

        # Display plugin information
        plugins = self.plugin_loader.get_plugin_info()
        self.logger.info("\nLoaded Plugins:")
        for plugin in plugins:
            status = "✓" if plugin['enabled'] else "✗"
            self.logger.info(
                f"  {status} {plugin['name']} - {plugin['category']} - {plugin['description']}"
            )

        self.session_manager.update_session(status=SessionStatus.RUNNING)

    async def run(self, resume_session_id: Optional[str] = None):
        """
        Run the penetration test

        Args:
            resume_session_id: Optional session ID to resume
        """
        if resume_session_id:
            await self.resume(resume_session_id)
            return

        self.is_running = True
        self.logger.info("\n" + "=" * 70)
        self.logger.info("Starting Penetration Test")
        self.logger.info("=" * 70 + "\n")

        start_time = datetime.now()

        try:
            # Get execution order
            execution_order = self.plugin_loader.get_execution_order()

            # Process each target
            for target in self.config.targets:
                if self.is_paused:
                    self.logger.warning("Scan paused by user")
                    self.session_manager.pause_session()
                    break

                self.logger.info(f"\n{'=' * 70}")
                self.logger.info(f"Target: {target.name} ({target.value})")
                self.logger.info(f"{'=' * 70}\n")

                # Run plugins in order
                for plugin_name in execution_order:
                    if self.is_paused:
                        break

                    plugin = self.plugin_loader.get_plugin(plugin_name)

                    if not plugin or not plugin.enabled:
                        continue

                    # Validate target
                    if not plugin.validate_target(target):
                        self.logger.debug(f"Plugin {plugin_name} skipped - target not valid")
                        continue

                    # Run plugin
                    await self._run_plugin(plugin, target)

            # Mark session as completed
            if not self.is_paused:
                self.session_manager.update_session(status=SessionStatus.COMPLETED)

        except KeyboardInterrupt:
            self.logger.warning("\nScan interrupted by user")
            self.session_manager.pause_session()

        except Exception as e:
            self.logger.error(f"Framework error: {e}")
            self.logger.debug(traceback.format_exc())
            self.session_manager.update_session(status=SessionStatus.FAILED)

        finally:
            self.is_running = False
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            self.logger.info("\n" + "=" * 70)
            self.logger.info("Scan Summary")
            self.logger.info("=" * 70)
            self.logger.info(f"Duration: {duration:.2f} seconds")
            self.logger.info(f"Targets scanned: {len(self.config.targets)}")
            self.logger.info(f"Plugins executed: {len(self.session.completed_plugins)}")
            self.logger.info(f"Vulnerabilities found: {self.session.total_vulnerabilities}")
            self.logger.info(f"Session ID: {self.session.session_id}")
            self.logger.info(f"Output directory: {self.output_dir}")

    async def _run_plugin(self, plugin: Any, target: Target):
        """Run a single plugin against a target"""
        plugin_start = datetime.now()

        try:
            self.logger.info(f"Running plugin: {plugin.name}")

            # Execute plugin
            result = await plugin.run(target)
            result.duration = (datetime.now() - plugin_start).total_seconds()

            # Store result
            self.results.append(result)
            self.session_manager.update_session(
                add_result=result.to_dict(),
                complete_plugin=plugin.name
            )

            # Log findings
            if result.vulnerabilities:
                self.logger.vuln_found(
                    f"Found {len(result.vulnerabilities)} vulnerabilities with {plugin.name}"
                )
                for vuln in result.vulnerabilities:
                    self.logger.warning(
                        f"  [{vuln['severity'].upper()}] {vuln['title']}"
                    )

            if result.errors:
                for error in result.errors:
                    self.logger.error(f"  Error: {error}")

            self.logger.success(f"Completed {plugin.name} in {result.duration:.2f}s")

        except asyncio.TimeoutError:
            self.logger.error(f"Plugin {plugin.name} timed out")
            self.session_manager.update_session(fail_plugin=plugin.name)

        except Exception as e:
            self.logger.error(f"Plugin {plugin.name} failed: {e}")
            self.logger.debug(traceback.format_exc())
            self.session_manager.update_session(fail_plugin=plugin.name)

        # Rate limiting
        if self.config.scan_mode.delay > 0:
            await asyncio.sleep(self.config.scan_mode.delay)

    async def resume(self, session_id: str):
        """Resume a paused session"""
        self.logger.info(f"Resuming session: {session_id}")

        session = self.session_manager.resume_session(session_id)
        if not session:
            self.logger.error("Session not found or cannot be resumed")
            return

        self.session = session

        # Filter out already completed plugins
        completed = set(session.completed_plugins)
        # Continue with remaining plugins
        # This is a simplified version - full implementation would restore state

        await self.run()

    def pause(self):
        """Pause the current scan"""
        self.is_paused = True
        self.logger.info("Pausing scan...")

    def get_results(self) -> List[PluginResult]:
        """Get all results"""
        return self.results

    def get_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Get all vulnerabilities found"""
        vulns = []
        for result in self.results:
            for vuln in result.vulnerabilities:
                vuln['target'] = result.target
                vuln['plugin'] = result.plugin_name
                vulns.append(vuln)
        return vulns

    def get_statistics(self) -> Dict[str, Any]:
        """Get scan statistics"""
        vulns = self.get_vulnerabilities()

        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }

        for vuln in vulns:
            severity = vuln.get('severity', 'info')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        return {
            'session_id': self.session.session_id,
            'status': self.session.status.value,
            'total_targets': len(self.config.targets),
            'total_plugins': len(self.plugin_loader.get_all_plugins()),
            'completed_plugins': len(self.session.completed_plugins),
            'failed_plugins': len(self.session.failed_plugins),
            'total_vulnerabilities': len(vulns),
            'severity_counts': severity_counts,
            'output_dir': str(self.output_dir)
        }
