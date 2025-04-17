import socket
import threading
from lib.comms import SecureChannel  
from lib.files import p2p_download_file, set_keys_from_secret

bot_port = 1337  


def scan_for_bot():  # Scans localhost for other bots and returns a SecureChannel
    print("Searching for active bot...")
    port = 1337

    while True:
        if port == bot_port:
            port += 1
            continue

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("localhost", port))
            secure = SecureChannel(sock, client=True)
            set_keys_from_secret(secure.shared_secret)
            print("Connected to peer on port %d" % port)
            return secure
        except socket.error:
            print("Port %d not responding..." % port)
            port += 1


def echo_mode(sconn):  # Echo mode: sends back received messages, handles 'replay' test triggers
    while True:
        incoming = sconn.recv()
        print("ECHO>", incoming)

        if incoming == b"replay":
            sconn.replay_last_received()
            continue

        sconn.send(incoming)

        if incoming == b"replay_recv":
            sconn.replay_last_received()

        if incoming in (b"X", b"exit", b"quit"):
            print("Terminating connection...")
            sconn.close()
            return


def handle_connection(sock):  # Wraps socket in SecureChannel and handles echo/file commands
    try:
        secure = SecureChannel(sock, server=True)
        set_keys_from_secret(secure.shared_secret)

        command = secure.recv()

        if command == b"ECHO":
            echo_mode(secure)
        elif command == b"FILE":
            p2p_download_file(secure)

    except socket.error:
        print("Peer disconnected unexpectedly.")
    except Exception as err:
        print("Secure session error:", err)


def launch_bot_server():  # Starts listener and accepts incoming secure connections on available port
    global bot_port
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    while True:
        try:
            listener.bind(("localhost", bot_port))
            print("Bot listening on port %d" % bot_port)
            break
        except socket.error:
            print("Port %d in use, trying next..." % bot_port)
            bot_port += 1

    listener.listen(5)

    while True:
        print("Awaiting new connection...")
        conn, addr = listener.accept()
        print("Connected by", addr)
        threading.Thread(target=handle_connection, args=(conn,)).start()
