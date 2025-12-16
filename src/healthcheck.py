"""
Healthcheck script for Docker
"""
import sys
import config
from lib.qbit import QbitManager

def check_health() -> None:
    """Check if the container is healthy."""
    
    # 1. Check Cookie presence (indicates successful login at some point)
    if not config.WS_COOKIE.exists():
        print("Unhealthy: Cookie file not found")
        sys.exit(1)

    # 2. Check QBitTorrent connectivity
    if config.qbit_found:
        try:
            QbitManager(
                host=config.QBIT_HOST,
                port=config.QBIT_PORT,
                username=config.QBIT_USERNAME,
                password=config.QBIT_PASSWORD,
            )
        except Exception as e:
            print(f"Unhealthy: QBitTorrent unreachable: {e}")
            sys.exit(1)
    
    print("Healthy")
    sys.exit(0)

if __name__ == "__main__":
    check_health()
