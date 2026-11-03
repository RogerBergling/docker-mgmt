"""Allow `python3 -m docker_mgmt`."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
