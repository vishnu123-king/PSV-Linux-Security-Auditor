from typing import Any, Dict
from backend.app.models.entities import VerificationStatus


class VerificationEngine:
    """
    Verifies finding remediation against target host.
    """

    def get_verification_command(self, control: str, verification_method: str) -> str:
        """Determines appropriate verification command line."""
        if "ssh." in control:
            return "sshd -T"
        elif "kernel." in control or "network." in control:
            param = control.replace("kernel.", "kernel.").replace("network.", "net.ipv4.")
            return f"sysctl {param}"
        elif "firewall." in control:
            return "ufw status verbose"
        elif "sudo." in control:
            return "sudo -V"
        return verification_method or "echo verified"


verification_engine = VerificationEngine()
