"""
logging.py - Structured logging configuration for Antigravity Unlocker System.
"""

import logging
from typing import Optional


def setup_logging(
    level_name: str = "INFO",
    logger_name: Optional[str] = None,
    include_timestamp: bool = True,
) -> logging.Logger:
    """Configures structured, non-interfering logging."""
    level = getattr(logging, level_name.upper(), logging.INFO)
    if include_timestamp:
        fmt = "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
        datefmt = "%Y-%m-%d %H:%M:%S"
    else:
        fmt = "%(levelname)s: %(message)s"
        datefmt = None

    logging.basicConfig(level=level, format=fmt, datefmt=datefmt)
    target_logger = logging.getLogger(logger_name if logger_name else "antigravity")
    target_logger.setLevel(level)
    return target_logger
