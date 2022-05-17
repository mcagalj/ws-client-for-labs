#!/usr/bin/env python3

"""
Based on wsdump.py
websocket - WebSocket client library for Python

Copyright 2022 engn33r

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import argparse
import code
import os
import sys
import threading
from argparse import RawTextHelpFormatter
from enum import Enum

from InquirerPy import inquirer
from InquirerPy.base.control import Choice
from InquirerPy.separator import Separator
from websocket import WebSocketApp, WebSocketConnectionClosedException


# Terminal color definitions
class fg:
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    RESET = "\033[39m"


class style:
    BRIGHT = "\033[1m"
    DIM = "\033[2m"
    NORMAL = "\033[22m"
    RESET_ALL = "\033[0m"


class Secure(Enum):
    PASS = "pass"
    ECDHE = "ecdhe"


def get_encoding():
    encoding = getattr(sys.stdin, "encoding", "")
    if not encoding:
        return "utf-8"
    else:
        return encoding.lower()


ENCODING = get_encoding()


def parse_args():
    parser = argparse.ArgumentParser(
        formatter_class=RawTextHelpFormatter, description="WebSocket Simple Chat"
    )
    parser.add_argument(
        "url",
        metavar="WS_URL",
        help="websocket url (eg. ws://10.0.2.4/ws/<client_id>)",
    )

    # parser.add_argument(
    #     "-s",
    #     "--secure",
    #     action="store",
    #     choices=["pass", "ecdhe"],
    #     help="Secure outbound messages.\n\n"
    #     "OPTIONS:\n"
    #     "{pass} - use a shared password to derive required secret keys.\n"
    #     "The password is provided through an environment variable WS_PASSWORD.\n\n"
    #     "{ecdhe} - use ephemeral elliptic curve Diffie-Hellman to establish secret keys.\n"
    #     "Diffie-Hellman ephemeral keys are signed by an appropriate elliptic curve-based signature algorithm ECDSA.\n"
    #     "Signature verification public keys are loaded from a YAML file settings.yaml.",
    # )

    return parser.parse_args()


class Action(Enum):
    CHAT = "Start chat"
    SECRETS = "Manage secrets"
    EXIT = "Exit"


class RawInput:
    def raw_input(self, prompt):
        line = input(prompt)

        if ENCODING and ENCODING != "utf-8" and not isinstance(line, str):
            line = line.decode(ENCODING).encode("utf-8")
        elif isinstance(line, str):
            line = line.encode("utf-8")

        return line


class InteractiveConsole(RawInput, code.InteractiveConsole):
    def write(self, data):
        sys.stdout.write("\033[2K\033[E")
        sys.stdout.write(fg.BLUE + style.BRIGHT + f"< {data}" + fg.RESET)
        sys.stdout.write("\n> ")
        sys.stdout.flush()

    def read(self):
        return self.raw_input("> ")


console = InteractiveConsole()


def on_message(ws, message):
    console.write(message)


def on_error(ws, error, stopped_event):
    stopped_event.set()
    print(fg.RED + f"{error}" + fg.RESET)


def on_open(ws, started_event):
    started_event.set()


def on_close(ws, stopped_event):
    stopped_event.set()
    print(fg.RED + "### connection closed ###" + fg.RESET)


def main():
    args = parse_args()
    if args.secure is not None:
        if args.secure == Secure.PASS.value:
            WS_PASSWORD = os.getenv("WS_PASSWORD")
            print(WS_PASSWORD)
        elif args.secure == Secure.ECDHE.value:
            pass

    header = {}

    print(fg.GREEN + "Press Ctrl+C to quit" + fg.RESET)
    print(fg.GREEN + "Connecting to server. Please wait ..." + fg.RESET)

    started_event = threading.Event()
    stopped_event = threading.Event()

    ws = WebSocketApp(
        url=args.url,
        header=header,
        on_message=on_message,
        on_open=lambda ws: on_open(ws, started_event),
        on_error=lambda ws, error: on_error(ws, error, stopped_event),
        on_close=lambda ws, *_: on_close(ws, stopped_event),
    )

    thread = threading.Thread(target=ws.run_forever)
    thread.daemon = True
    thread.start()
    try:
        while True:
            selected_action = inquirer.select(
                message="Select your action:",
                choices=[
                    Separator(),
                    Choice(value=Action.CHAT, name=Action.CHAT.value),
                    Choice(value=Action.SECRETS, name=Action.SECRETS.value),
                    Choice(value=Action.EXIT, name=Action.EXIT.value),
                ],
            ).execute()

            if selected_action == Action.CHAT:
                started_event.wait(timeout=5)
                while not stopped_event.is_set():
                    try:
                        message = console.read()
                        # message = b64encode(message)
                        ws.send(message)
                    except KeyboardInterrupt:
                        break
                    except EOFError:
                        return
                    except WebSocketConnectionClosedException:
                        return
            elif selected_action == Action.EXIT:
                sys.exit(0)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(e)
