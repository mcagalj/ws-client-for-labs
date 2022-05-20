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
import sys
import threading
from argparse import RawTextHelpFormatter
from enum import Enum

from InquirerPy import inquirer
from InquirerPy.base.control import Choice
from InquirerPy.separator import Separator
from InquirerPy.validator import EmptyInputValidator
from tabulate import tabulate
from websocket import WebSocketApp, WebSocketConnectionClosedException

from .crypto import InvalidToken
from .processor import MessageProcessor
from .schemas import Message
from .utils import base64_decode


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


class Action(Enum):
    CHAT = "Talk to others"
    USERS = "Manage users"
    SHOW_USERS = "Show users"
    ADD_USER = "Add/update a user (her secret)"
    DELETE_USER = "Remove a user"
    EXIT = "Exit"


class RawInput:
    def raw_input(self, prompt):
        line = input(prompt)
        ENCODING = RawInput.get_encoding()
        if ENCODING and ENCODING != "utf-8" and not isinstance(line, str):
            line = line.decode(ENCODING).encode("utf-8")
        elif isinstance(line, str):
            line = line.encode("utf-8")

        return line

    @staticmethod
    def get_encoding():
        encoding = getattr(sys.stdin, "encoding", "")
        if not encoding:
            return "utf-8"
        else:
            return encoding.lower()


class InteractiveConsole(RawInput, code.InteractiveConsole):
    def write(self, data):
        sys.stdout.write("\033[2K\033[E")
        sys.stdout.write(fg.BLUE + style.BRIGHT + f"< {data}" + fg.RESET)
        sys.stdout.write("\n> ")
        sys.stdout.flush()

    def read(self):
        return self.raw_input("> ")


console = InteractiveConsole()


def parse_args():
    parser = argparse.ArgumentParser(
        formatter_class=RawTextHelpFormatter,
        description="WebSocket Simple Chat",
    )
    parser.add_argument(
        "url",
        metavar="WS_URL",
        help="websocket url (eg. ws://10.0.2.4/ws/<client_id>)",
    )
    return parser.parse_args()


def on_message(ws, message, users):
    print(message)
    try:
        token = message.split(":")[-1].strip()
        # username = base64_decode(token.split(".")[0]).decode()
        username = base64_decode(token.split(".")[0])[8:].decode()
        print(username)
        processor = users.get(username)

        if processor is not None:
            processed_message = processor.process_inbound(token)
            console.write(
                fg.RED
                + f"#{username}: "
                + fg.RESET
                + processed_message.plaintext.decode()
            )
        else:
            console.write(message)

    except InvalidToken:
        console.write(fg.RED + f"#{username}: Invalid Token" + fg.RESET)
        return
    except Exception:
        console.write(message)


def on_error(ws, error, stopped_event):
    stopped_event.set()
    print(fg.RED + f"{error}" + fg.RESET)


def on_open(ws, started_event):
    started_event.set()
    print(fg.GREEN + "Successfully connected to the server.\n" + fg.RESET)


def on_close(ws, stopped_event):
    stopped_event.set()
    print(fg.RED + "### connection closed ###" + fg.RESET)


def do_start_chat(**kwargs):
    username = kwargs.get("username")
    users = kwargs.get("users")
    stopped_event = kwargs.get("stopped_event")
    console = kwargs.get("console")
    ws = kwargs.get("ws")

    processor = users.get(username)

    while not stopped_event.is_set():
        try:
            message = console.read()
            if processor is not None:
                message = processor.process_outbound(
                    Message(
                        plaintext=message,
                        associated_data=username,
                    )
                )
            ws.send(message)
        except KeyboardInterrupt:
            break
        except EOFError:
            return
        except WebSocketConnectionClosedException:
            return


def _separator(items):
    if isinstance(items, str):
        return Separator(line=f"----- {items} -----")
    elif isinstance(items, list):
        breadcrumb = " > ".join(items)
        print(Separator(line=f"----- {breadcrumb} -----"))


def do_manage_users(**kwargs):
    breadcrumb_root = kwargs.get("breadcrumb")
    stopped_event = kwargs.get("stopped_event")
    users = kwargs.get("users")

    while not stopped_event.is_set():
        try:
            breadcrumb = f"{breadcrumb_root} > {Action.USERS.value}"
            action = inquirer.select(
                message="Select your action:",
                choices=[
                    _separator(breadcrumb),
                    Choice(
                        value=Action.ADD_USER,
                        name=Action.ADD_USER.value,
                    ),
                    Choice(
                        value=Action.SHOW_USERS,
                        name=Action.SHOW_USERS.value,
                    ),
                    Choice(
                        value=Action.DELETE_USER,
                        name=Action.DELETE_USER.value,
                    ),
                    Choice(
                        value=Action.EXIT,
                        name=Action.EXIT.value,
                    ),
                ],
            ).execute()

            if action == Action.ADD_USER:
                try:
                    _separator([breadcrumb, Action.ADD_USER.value])
                    username = (
                        inquirer.text(
                            message="Enter a user username:",
                            validate=EmptyInputValidator(),
                        )
                        .execute()
                        .strip()
                    )
                    secret = (
                        inquirer.secret(
                            message=f"Enter a secret for user '{username}':",
                            validate=EmptyInputValidator(),
                        )
                        .execute()
                        .strip()
                    )

                    if users.get(username) is not None:
                        users.get(username).secret = secret
                    else:
                        users.update(
                            {
                                username: MessageProcessor(
                                    secret=secret, username=username
                                )
                            }
                        )
                except KeyboardInterrupt:
                    pass
            elif action == Action.DELETE_USER:
                try:
                    _separator([breadcrumb, Action.DELETE_USER.value])
                    username = (
                        inquirer.text(message="Enter a username you want to delete:")
                        .execute()
                        .strip()
                    )
                    users.pop(username, None)
                except KeyboardInterrupt:
                    pass
            elif action == Action.SHOW_USERS:
                print(
                    tabulate(
                        [[c, s] for c, s in users.items()],
                        headers=["Client name", "Secret"],
                        tablefmt="fancy_grid",
                    )
                )
            elif action == Action.EXIT:
                break
        except KeyboardInterrupt:
            break


def parse_username(url):
    return url.split("/")[-1]


def main():
    args = parse_args()
    username = parse_username(args.url)
    users = {}  # holds references to users's message processors

    print(fg.RED + "Press Ctrl+C to quit" + fg.RESET)
    print(fg.GREEN + "Connecting to server. Please wait ..." + fg.RESET)

    started_event = threading.Event()
    stopped_event = threading.Event()

    ws = WebSocketApp(
        url=args.url,
        header={},
        on_message=lambda ws, message: on_message(ws, message, users),
        on_open=lambda ws: on_open(ws, started_event),
        on_error=lambda ws, error: on_error(ws, error, stopped_event),
        on_close=lambda ws, *_: on_close(ws, stopped_event),
    )

    thread = threading.Thread(target=ws.run_forever)
    thread.daemon = True
    thread.start()

    started_event.wait(timeout=5)

    try:
        breadcrumb = "Main menu"
        while not stopped_event.is_set():
            action = inquirer.select(
                message="Select your action:",
                choices=[
                    _separator(breadcrumb),
                    Choice(value=Action.CHAT, name=Action.CHAT.value),
                    Choice(value=Action.USERS, name=Action.USERS.value),
                    Choice(value=Action.EXIT, name=Action.EXIT.value),
                ],
            ).execute()

            if action == Action.CHAT:
                do_start_chat(
                    username=username,
                    users=users,
                    stopped_event=stopped_event,
                    console=console,
                    ws=ws,
                )
            elif action == Action.USERS:
                do_manage_users(
                    users=users,
                    breadcrumb=breadcrumb,
                    stopped_event=stopped_event,
                )
            elif action == Action.EXIT:
                sys.exit(0)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(e)
