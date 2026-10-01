"""
DISPOSABLE DEVELOPMENT TEST TARGET GENERATOR (TEST ENVIRONMENT ONLY)

Generates intentional, non-destructive configuration artifacts for testing
auditing logic and verification workflows.

DO NOT RUN ON PRODUCTION SYSTEMS.
"""

import sys

def main():
    print("================================================================")
    print("      PSV LINUX SECURITY AUDITOR - TEST ENVIRONMENT ONLY        ")
    print("================================================================")
    print("This utility provides mock and disposable target facts for testing.")
    print("Controlled test parameters generated:")
    print("  - SSH PermitRootLogin: yes")
    print("  - SSH PasswordAuthentication: yes")
    print("  - Sudo wildcard NOPASSWD: true")
    print("  - Network IP forwarding: 1")
    print("  - UFW Firewall: inactive")
    print("Ready for automated evaluation by PSV collectors.")

if __name__ == "__main__":
    main()
