import socket
import time
import threading

from lib.evil import bitcoin_mine, harvest_user_pass
from lib.p2p import scan_for_bot, launch_bot_server
from lib.files import (
    filestore, valuables,
    set_keys_from_secret,
    p2p_upload_file,
    upload_valuables_to_pastebot,
    download_from_pastebot,
    save_valuable
)


def p2p_upload(fn):  # Sends a file to another bot securely (Tasks 2 & 3)
    if fn not in filestore:
        print("File not found in local filestore")
        return

    sconn = scan_for_bot()
    if sconn:
        set_keys_from_secret(sconn.shared_secret)
        sconn.send(b"FILE")
        p2p_upload_file(sconn, fn)


def p2p_echo():  # Starts encrypted echo session with another bot (Tasks 2 & 3)
    try:
        sconn = scan_for_bot()
        if sconn:
            set_keys_from_secret(sconn.shared_secret)
            sconn.send(b"ECHO")

            while True:
                msg = input("Echo> ").encode("ascii")
                sconn.send(msg)
                reply = sconn.recv()

                if reply != msg:
                    print("[warning] Echo mismatch — integrity may be compromised")
                else:
                    print("[ok] Echo successful")

                if msg.lower() in (b"x", b"exit", b"quit"):
                    sconn.close()
                    break
    except socket.error:
        print("Connection dropped unexpectedly")


if __name__ == "__main__":  # Main interactive loop for bot commands
    server_thread = threading.Thread(target=launch_bot_server)
    server_thread.daemon = True
    server_thread.start()
    time.sleep(0.3)

    while True:
        raw_input = input("Enter command: ")
        tokens = raw_input.strip().split()

        if not tokens:
            print("Please enter a command.")
            continue

        cmd = tokens[0].lower()

        if cmd == "p2p":
            if len(tokens) > 1:
                sub = tokens[1].lower()
                if sub == "echo":
                    p2p_echo()
                elif sub == "upload":
                    if len(tokens) == 3:
                        p2p_upload(tokens[2])
                    else:
                        print("Usage: p2p upload <filename>")
                else:
                    print("Unknown p2p subcommand")
            else:
                print("Specify either 'echo' or 'upload' after 'p2p'")

        elif cmd == "download":  # Downloads file from pastebot
            if len(tokens) == 2:
                download_from_pastebot(tokens[1])
            else:
                print("Usage: download <filename>")

        elif cmd == "upload":  # Uploads valuables to pastebot
            if len(tokens) == 2:
                upload_valuables_to_pastebot(tokens[1])
            else:
                print("Usage: upload <filename>")

        elif cmd == "mine":  # Simulates Bitcoin mining (Task 4)
            print("Mining in progress...")
            btc = bitcoin_mine()
            save_valuable(f"Bitcoin: {btc}")
            print("Generated fake Bitcoin address:", btc)

        elif cmd == "harvest":  # Simulates credential harvesting (Task 4)
            creds = harvest_user_pass()
            save_valuable(f"Username/Password: {creds[0]} {creds[1]}")
            print("Harvested credentials:", creds)

        elif cmd == "list":  # Lists local files and harvested data
            print("Local files:", ", ".join(filestore.keys()))
            print("Valuables:", valuables)

        elif cmd in ("exit", "quit"):  # Exits the bot CLI
            break

        else:
            print("Unknown command")
