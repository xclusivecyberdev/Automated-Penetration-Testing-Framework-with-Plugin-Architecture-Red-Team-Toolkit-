"""
Session management for tracking and resuming scans
"""

import json
import pickle
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict
from enum import Enum


class SessionStatus(Enum):
    """Session status"""
    CREATED = "created"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class SessionInfo:
    """Session information"""
    session_id: str
    name: str
    created_at: datetime
    status: SessionStatus
    targets: List[Dict[str, Any]] = field(default_factory=list)
    completed_plugins: List[str] = field(default_factory=list)
    failed_plugins: List[str] = field(default_factory=list)
    results: List[Dict[str, Any]] = field(default_factory=list)
    total_vulnerabilities: int = 0
    updated_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['created_at'] = self.created_at.isoformat()
        data['status'] = self.status.value
        if self.updated_at:
            data['updated_at'] = self.updated_at.isoformat()
        if self.completed_at:
            data['completed_at'] = self.completed_at.isoformat()
        return data


class SessionManager:
    """Manages scan sessions for pause/resume functionality"""

    def __init__(self, session_dir: str = "sessions"):
        self.session_dir = Path(session_dir)
        self.session_dir.mkdir(exist_ok=True)
        self.current_session: Optional[SessionInfo] = None

    def create_session(self, name: Optional[str] = None) -> SessionInfo:
        """Create a new session"""
        timestamp = datetime.now()
        session_id = timestamp.strftime("%Y%m%d_%H%M%S")

        if not name:
            name = f"scan_{session_id}"

        session = SessionInfo(
            session_id=session_id,
            name=name,
            created_at=timestamp,
            status=SessionStatus.CREATED
        )

        self.current_session = session
        self._save_session(session)

        return session

    def load_session(self, session_id: str) -> Optional[SessionInfo]:
        """Load an existing session"""
        session_file = self.session_dir / f"{session_id}.json"

        if not session_file.exists():
            return None

        try:
            with open(session_file, 'r') as f:
                data = json.load(f)

            session = SessionInfo(
                session_id=data['session_id'],
                name=data['name'],
                created_at=datetime.fromisoformat(data['created_at']),
                status=SessionStatus(data['status']),
                targets=data.get('targets', []),
                completed_plugins=data.get('completed_plugins', []),
                failed_plugins=data.get('failed_plugins', []),
                results=data.get('results', []),
                total_vulnerabilities=data.get('total_vulnerabilities', 0),
                updated_at=datetime.fromisoformat(data['updated_at']) if data.get('updated_at') else None,
                completed_at=datetime.fromisoformat(data['completed_at']) if data.get('completed_at') else None
            )

            self.current_session = session
            return session

        except Exception as e:
            print(f"Error loading session: {e}")
            return None

    def update_session(
        self,
        status: Optional[SessionStatus] = None,
        add_result: Optional[Dict[str, Any]] = None,
        complete_plugin: Optional[str] = None,
        fail_plugin: Optional[str] = None
    ):
        """Update the current session"""
        if not self.current_session:
            return

        if status:
            self.current_session.status = status

        if add_result:
            self.current_session.results.append(add_result)
            # Count vulnerabilities
            vuln_count = len(add_result.get('vulnerabilities', []))
            self.current_session.total_vulnerabilities += vuln_count

        if complete_plugin:
            self.current_session.completed_plugins.append(complete_plugin)

        if fail_plugin:
            self.current_session.failed_plugins.append(fail_plugin)

        self.current_session.updated_at = datetime.now()

        if status == SessionStatus.COMPLETED:
            self.current_session.completed_at = datetime.now()

        self._save_session(self.current_session)

    def pause_session(self):
        """Pause the current session"""
        if self.current_session:
            self.update_session(status=SessionStatus.PAUSED)

    def resume_session(self, session_id: str) -> Optional[SessionInfo]:
        """Resume a paused session"""
        session = self.load_session(session_id)
        if session and session.status == SessionStatus.PAUSED:
            self.update_session(status=SessionStatus.RUNNING)
            return session
        return None

    def list_sessions(self) -> List[Dict[str, Any]]:
        """List all sessions"""
        sessions = []

        for session_file in self.session_dir.glob("*.json"):
            try:
                with open(session_file, 'r') as f:
                    data = json.load(f)
                    sessions.append(data)
            except Exception:
                continue

        # Sort by creation date, newest first
        sessions.sort(key=lambda x: x['created_at'], reverse=True)

        return sessions

    def get_session_state(self) -> Optional[Dict[str, Any]]:
        """Get the current session state"""
        if not self.current_session:
            return None

        return self.current_session.to_dict()

    def _save_session(self, session: SessionInfo):
        """Save session to disk"""
        session_file = self.session_dir / f"{session.session_id}.json"

        with open(session_file, 'w') as f:
            json.dump(session.to_dict(), f, indent=2)

    def save_checkpoint(self, data: Any):
        """Save a checkpoint with arbitrary data"""
        if not self.current_session:
            return

        checkpoint_file = self.session_dir / f"{self.current_session.session_id}_checkpoint.pkl"

        with open(checkpoint_file, 'wb') as f:
            pickle.dump(data, f)

    def load_checkpoint(self, session_id: str) -> Optional[Any]:
        """Load checkpoint data"""
        checkpoint_file = self.session_dir / f"{session_id}_checkpoint.pkl"

        if not checkpoint_file.exists():
            return None

        try:
            with open(checkpoint_file, 'rb') as f:
                return pickle.load(f)
        except Exception:
            return None

    def delete_session(self, session_id: str) -> bool:
        """Delete a session"""
        session_file = self.session_dir / f"{session_id}.json"
        checkpoint_file = self.session_dir / f"{session_id}_checkpoint.pkl"

        deleted = False

        if session_file.exists():
            session_file.unlink()
            deleted = True

        if checkpoint_file.exists():
            checkpoint_file.unlink()

        return deleted
