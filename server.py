from socket import *
import subprocess
from threading import Thread
from ssl import SSLContext, PROTOCOL_TLS_SERVER

PORT = 4422
MESSAGE_LENGTH_SIZE = 64
ENCODING = "utf-8"


def main():
    address = gethostbyname(gethostname())
    HOST_INFORMATION = (address, PORT)

    s = socket(AF_INET, SOCK_STREAM)
    s.bind(HOST_INFORMATION)
    s.listen(2)

    print('\nWaiting for Clients to Connect...')

    while True:
        conn, addr = s.accept()
        Thread(target=client_handler, args=(conn, addr)).start()


def client_handler(conn, addr):
    print("\n[NEW CONNECTION] from {}".format(addr))
    connected = True

    while connected:

        cmd_length = int(conn.recv(MESSAGE_LENGTH_SIZE).decode(ENCODING))
        cmd = conn.recv(cmd_length).decode(ENCODING)

        # Disconnection
        if cmd == "disconnect":
            print("[DISCONNECTED!] {}\n".format(addr))
            connected = False

        # Receive Text Message
        elif cmd == "send":
            message_length = int(conn.recv(MESSAGE_LENGTH_SIZE).decode(ENCODING))
            msg = conn.recv(message_length).decode(ENCODING)
            print("\n[MESSAGE RECEIVED]: {}\n".format(msg))

        # Receive File
        elif cmd == "upload":
            file_name_length = int(conn.recv(MESSAGE_LENGTH_SIZE).decode(ENCODING))
            file_name = conn.recv(file_name_length).decode(ENCODING)

            f = open(file_name, "wb")  # Open in binary
            file_length = int(conn.recv(MESSAGE_LENGTH_SIZE).decode(ENCODING))
            while True:
                content = conn.recv(1024)
                file_length -= 1024

                if file_length <= 0:
                    break

                f.write(content)
            f.close()

            print("\n[FILE RECEIVED]: {}\n".format(file_name))

        # Exec
        elif cmd == "exec":
            message_length = int(conn.recv(MESSAGE_LENGTH_SIZE).decode(ENCODING))
            msg = conn.recv(message_length).decode(ENCODING)
            print("\n[EXEC CMD RECEIVED]: {}\n".format(msg))

            sub = subprocess.Popen(msg, shell=True, stdout=subprocess.PIPE)
            subprocess_return = sub.stdout.read()
            # print(subprocess_return)
            # print(subprocess_return.decode("utf-8"))
            msg = subprocess_return.decode("utf-8")
            msg_length, message = input_message(msg)
            # print(msg)
            conn.send(msg_length)
            conn.send(message)
            # os.system(str(msg))

        elif cmd == "send-e":
            ip = '127.0.0.1'
            port = 8443
            context = SSLContext(PROTOCOL_TLS_SERVER)
            context.load_cert_chain('cert.pem', 'key.pem')

            with socket(AF_INET, SOCK_STREAM) as server:
                server.bind((ip, port))
                server.listen(1)
                with context.wrap_socket(server, server_side=True) as tls:
                    connection, address = tls.accept()

                    message_length = int(connection.recv(MESSAGE_LENGTH_SIZE).decode(ENCODING))
                    msg = connection.recv(message_length).decode(ENCODING)
                    print("[ENCRYPTED MESSAGE RECEIVED]: {}".format(msg))

                    tls.close()
                    connection.close()
                    server.close()


def input_message(msg):
    message = msg.encode(ENCODING)
    msg_length = len(message)
    msg_length = str(msg_length).encode(ENCODING)
    msg_length += b' ' * (MESSAGE_LENGTH_SIZE - len(msg_length))

    return msg_length, message


if __name__ == '__main__':
    main()
