from datetime import datetime


class AdminActionLog:
    """
    Represents an administrative action performed on the system.
    """

    def __init__(
        self,
        *,
        admin_id: str,
        action: str,
        target_type: str,
        target_id: str,
    ):
        self.admin_id = admin_id
        self.action = action
        self.target_type = target_type
        self.target_id = target_id
        self.timestamp = datetime.utcnow()

    def to_dict(self) -> dict:
        return {
            "admin_id": self.admin_id,
            "action": self.action,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "timestamp": self.timestamp,
        }
