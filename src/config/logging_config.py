"""
Logging configuration for the GainForest Archival Pipeline
"""
import logging
import logging.handlers
from pathlib import Path
from typing import Optional
from rich.logging import RichHandler
from rich.console import Console
from datetime import datetime


def setup_logging(
        log_level: str = "INFO",
        log_dir: Optional[Path] = None,
        log_to_file: bool = True,
        log_to_console: bool = True,
        app_name: str = "gainforest-archival"
) -> logging.Logger:
    """
    Configure logging with both file and console handlers

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_dir: Directory for log files
        log_to_file: Enable file logging
        log_to_console: Enable console logging
        app_name: Application name for logger

    Returns:
        logging.Logger: Configured logger instance
    """
    logger = logging.getLogger(app_name)
    logger.setLevel(getattr(logging, log_level.upper()))

    logger.handlers.clear()

    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    if log_to_file and log_dir:
        log_dir = Path(log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d")
        log_file = log_dir / f"{app_name}_{timestamp}.log"

        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setFormatter(file_formatter)
        file_handler.setLevel(logging.DEBUG)
        logger.addHandler(file_handler)

        error_log_file = log_dir / f"{app_name}_errors_{timestamp}.log"
        error_handler = logging.handlers.RotatingFileHandler(
            error_log_file,
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding='utf-8'
        )
        error_handler.setFormatter(file_formatter)
        error_handler.setLevel(logging.ERROR)
        logger.addHandler(error_handler)

    if log_to_console:
        console = Console(stderr=True)
        console_handler = RichHandler(
            console=console,
            rich_tracebacks=True,
            tracebacks_show_locals=True,
            markup=True,
            show_time=True,
            show_path=True
        )
        console_handler.setLevel(getattr(logging, log_level.upper()))
        logger.addHandler(console_handler)

    logger.info(f"Logging initialized for {app_name} at level {log_level}")

    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for a specific module

    Args:
        name: Module name for the logger

    Returns:
        logging.Logger: Logger instance
    """
    return logging.getLogger(f"gainforest-archival.{name}")
