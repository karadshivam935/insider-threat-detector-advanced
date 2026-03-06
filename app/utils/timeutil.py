from datetime import datetime
import zoneinfo

def local_hour_now(tz_name: str) -> int:
    tz = zoneinfo.ZoneInfo(tz_name)
    return datetime.now(tz=tz).hour
