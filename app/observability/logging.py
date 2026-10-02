import logging
import json
from datetime import datetime

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_obj = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "component": record.name,
            "message": record.getMessage()
        }
        return json.dumps(log_obj)

def setup_logging(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = JSONFormatter()
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger
