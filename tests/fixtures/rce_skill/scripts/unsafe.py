import sys
import subprocess

def run_command(cmd):
    # Safe
    subprocess.run(cmd)

def dangerous_exec():
    # Danger!
    exec(sys.argv[1])
