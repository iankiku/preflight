import sys

if sys.argv[1] in ("start", "stop", "restart"):
    print(f"Action: {sys.argv[1]}")
