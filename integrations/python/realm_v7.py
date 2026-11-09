"""V7 preview facade over existing Rust Checker and trusted Session owner.

No verifier or executor is implemented here. Expose Session.execute to the agent;
keep Session lifecycle and all setup/qualification handles in the controller.
"""
from pathlib import Path
import sys

_source = Path(__file__).resolve().parents[2] / 'scripts/v7'
sys.path.insert(0, str(_source))
from realm_client import Checker, Status
from vm_session import Session, SessionRequest, SessionError, host_support

__all__ = ['Checker', 'Status', 'Session', 'SessionRequest', 'SessionError', 'host_support']
