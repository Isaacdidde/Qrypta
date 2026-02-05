from datetime import datetime
import pytz

IST = pytz.timezone("Asia/Kolkata")
UTC = pytz.utc

def utc_to_ist(dt: datetime | None):
    if dt is None:
        return None

    # Ensure datetime is UTC-aware
    if dt.tzinfo is None:
        dt = UTC.localize(dt)

    return dt.astimezone(IST)
