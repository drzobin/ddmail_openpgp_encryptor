import sys
import os
import argparse
import logging
import logging.handlers
import asyncio
import toml
from logging import FileHandler
from aiosmtpd.controller import Controller
from ddmail_openpgp_encryptor.ddmail_handler import Ddmail_handler

async def run(loop, logger, config):
    handler = Ddmail_handler(logger, config)
    controller = Controller(handler, hostname=config["LISTEN_ON_IP"], port=int(config["LISTEN_ON_PORT"]))
    controller.start()

    # Run forever.
    try:
        await asyncio.Event().wait()
    finally:
        controller.stop()

def main():
    # Get arguments from args.
    parser = argparse.ArgumentParser(description="Encrypt email with OpenPGP for ddmail service.")
    parser.add_argument('--config-file', type=str, help='Full path to config file.', required=True)
    args = parser.parse_args()

    # Check that config file exists and is a file.
    if not os.path.isfile(args.config_file):
        print("ERROR: config file does not exist or is not a file.")
        sys.exit(1)

    # Parse toml config file.
    with open(args.config_file, 'r') as f:
        toml_config = toml.load(f)

    # Setup logging.
    logger = logging.getLogger(__name__)

    formatter = logging.Formatter(
        "{asctime} ddmail_openpgp_encryptor {levelname} in {module} {funcName} {lineno}: {message}",
        style="{",
        datefmt="%Y-%m-%d %H:%M",
        )

    if toml_config["LOGGING"]["LOG_TO_CONSOLE"] == True:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    if toml_config["LOGGING"]["LOG_TO_FILE"] == True:
        file_handler = logging.FileHandler(toml_config["LOGGING"]["LOGFILE"], mode="a", encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    if toml_config["LOGGING"]["LOG_TO_SYSLOG"] == True:
        syslog_handler = logging.handlers.SysLogHandler(address = toml_config["LOGGING"]["SYSLOG_SERVER"])
        syslog_handler.setFormatter(formatter)
        logger.addHandler(syslog_handler)

    # Set loglevel.
    if toml_config["LOGGING"]["LOGLEVEL"] == "DEBUG":
        logger.setLevel(logging.DEBUG)
    elif toml_config["LOGGING"]["LOGLEVEL"] == "INFO":
        logger.setLevel(logging.INFO)
    elif toml_config["LOGGING"]["LOGLEVEL"] == "WARNING":
        logger.setLevel(logging.WARNING)
    elif toml_config["LOGGING"]["LOGLEVEL"] == "ERROR":
        logger.setLevel(logging.ERROR)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(run(loop, logger, toml_config))


if __name__ == "__main__":
    main()
