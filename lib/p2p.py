import socket
import threading

from lib.comms import SecureChannel  # Secure version of connection (AES + HMAC + replay)
from lib.files import p2p_download_file, set_keys_from_secret

# Track the port we bind to so we don’t connect to ourselves
server_port = 1337


def find_bot():
    """
    Search for another bot listening on localhost,
    skipping our own port.
    """
    print("Finding another bot...")
    port = 1337
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    while True:
        if port == server_port:
            port += 1
            continue

        try:
            conn.connect(("localhost", port))
            sconn = SecureChannel(conn, client=True)

            # Inject shared secret for file encryption/HMAC
            set_keys_from_secret(sconn.shared_secret)

            print("Found bot on port %d" % port)
            return sconn
        except socket.error:
            print("No bot was listening on port %d" % port)
            port += 1


def echo_server(sconn):
    """
    Echoes messages back to the sender until termination signal is received.
    """
    while True:
        data = sconn.recv()
        print("ECHOING>", data)
        sconn.send(data)

        if data in (b"X", b"exit", b"quit"):
            print("Closing connection...")
            sconn.close()
            return


def accept_connection(conn):
    """
    Accept an incoming socket connection and route it
    to either echo or file download logic.
    """
    try:
        sconn = SecureChannel(conn, server=True)

        # Set up lib.files' encryption system with shared secret
        set_keys_from_secret(sconn.shared_secret)

        cmd = sconn.recv()

        if cmd == b"ECHO":
            echo_server(sconn)
        elif cmd == b"FILE":
            p2p_download_file(sconn)
    except socket.error:
        print("Connection closed unexpectedly")
    except Exception as e:
        print("Secure connection error:", e)


def bot_server():
    """
    Runs a threaded socket server to accept connections from other bots.
    """
    global server_port
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    while True:
        try:
            s.bind(("localhost", server_port))
            print("Listening on port %d" % server_port)
            break
        except socket.error:
            print("Port %d not available" % server_port)
            server_port += 1

    s.listen(5)

    while True:
        print("Waiting for connection...")
        conn, address = s.accept()
        print("Accepted a connection from %s..." % (address,))
        threading.Thread(target=accept_connection, args=(conn,)).start()
