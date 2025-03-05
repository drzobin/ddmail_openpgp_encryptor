import sys
import os
import argparse
import logging
import asyncio
import configparser
from aiosmtpd.controller import Controller
from ddmail_openpgp_encryptor.ddmail_handler import Ddmail_handler

async def run(loop, logging, config):
    handler = Ddmail_handler(logging, config)
    controller = Controller(handler, hostname=config["DEFAULT"]["listen_on_ip"], port=int(config["DEFAULT"]["listen_on_port"]))
    controller.start()

    # Run forever.
    try:
        await asyncio.Event().wait()
    finally:
        controller.stop()

def main():
    # Configure logging.
    logging.basicConfig(filename="/var/log/ddmail_openpgp_encryptor.log", format='%(asctime)s: %(levelname)s: %(message)s', level=logging.INFO)
    logging.info("openpgp_encryptor starting")
    
    # Get arguments from args.
    parser = argparse.ArgumentParser(description="Encrypt email with OpenPGP for ddmail service.")
    parser.add_argument('--config-file', type=str, help='Full path to config file.', required=True)
    args = parser.parse_args()

    # Check that config file exists and is a file.
    if not os.path.isfile(args.config_file):
        logging.error("config file does not exist or is not a file.")
        sys.exit(1)

    # Import config file.
    config = configparser.ConfigParser()
    conf_file = args.config_file
    config.read(conf_file)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(run(loop, logging, config))


if __name__ == "__main__":
    main()
