from socket import *
import os
import sys
from time import sleep

import mysql.connector
from ssl import SSLContext, PROTOCOL_TLS_CLIENT

'''
c = socket.socket("Network Layer Protocol", "Transport Layer Protocol")

s.bind(Host, Port)  #Server side

s.connect("Host Information")   #Client side
'''

PORT = 4422
MESSAGE_LENGTH_SIZE = 64
ENCODING = "utf-8"
connected = True
# SECTION =
cmd_history = []


def main():
    # internet_connection()
    while True:
        option = input("\n> Choose an Option:\n  1.Local Connection or  2.Internet Connection or "
                       " 3.Find Open Ports  or  4.'terminate' to Terminate the Program\n > ")

        # Program Termination
        if option == "terminate":
            break

        # Local Connection
        elif option == "1":
            address = gethostbyname(gethostname())
            SERVER_INFORMATION = (address, PORT)

            s = socket(AF_INET, SOCK_STREAM)
            s.connect(SERVER_INFORMATION)

            print('[CONNECTED TO] ' + address + " on port " + str(PORT))

            while connected:
                command = input("\n > Enter your command: ")
                write_into_history_db(command)
                send_msg(s, command)

        # Internet Connection
        elif option == "2":
            internet_connection()

        # Find Open Ports
        elif option == "3":
            write_into_history_db("Find Open Ports")

            host = input(' > Host: ')
            start_port = input(' > Start Port: ')
            final_port = input(' > Final Port: ')
            print("\n> Checking Open Ports.\n  It may take a few seconds...")
            print("Open Ports are:\n", find_open_ports(host, start_port, final_port))

        # Invalid Input
        else:
            print("Invalid Input. Try Again!")


def internet_connection():
    terminated = False

    host = input(" > Enter the hostname: ")
    port = input(" > Enter the port: ")

    # create socket
    print('# Creating socket')
    try:
        s = socket(AF_INET, SOCK_STREAM)
    except error:
        print('Failed to create socket')
        sys.exit()

    print('# Getting remote IP address')
    try:
        remote_ip = gethostbyname(host)
    except gaierror:
        print('Hostname could not be resolved. Exiting')
        sys.exit()

    # Connect to remote server
    print('# Connecting to server, ' + host + ' (' + remote_ip + ')')
    s.connect((remote_ip, int(port)))

    if port == "25":
        print('# Receive data from server')
        reply = s.recv(1024 * 5)
        write_into_log_db(reply)
        print(reply.decode("utf-8"))

    # Send data to remote server
    print('# Sending data to server')
    while not terminated:
        # request = "GET / HTTP/1.0\r\n\r\n"
        print("\n > Request: ")
        request = ""

        while True:
            char_in = input(" > ")
            if char_in == "*":
                request += "\r\n"
            elif char_in == "$":
                break
            else:
                request += char_in

        write_into_history_db(request)

        if request == "history":
            print("##Command History from Database")
            records = "SELECT * FROM history "
            cursor.execute(records)
            for (record) in cursor:
                print(record[0], record[1])

            continue

        elif request == "quit\r\n" or request == "QUIT\r\n":
            if port == "80":
                break
            terminated = True

        try:
            write_into_log_db(request.encode("utf-8"))
            s.sendall(request.encode("utf-8"))
        except error:
            print('Send failed')
            sys.exit()

        # Receive data
        print('# Receive data from server')
        reply = s.recv(4096)
        write_into_log_db(reply)
        print(reply.decode("utf-8"))


def send_msg(sock, command):
    if command == "send" or command == "disconnect" or command == "upload" or command == "exec" or command == "send-e":
        msg = command
        cmd_length, message = input_message(msg)
        sock.send(cmd_length)
        sock.send(message)

        write_into_log_db(cmd_length)
        write_into_log_db(message)

    if command == "send":
        msg = input(" > ")
        msg_length, message = input_message(msg)
        sock.send(msg_length)
        sock.send(message)

        write_into_log_db(msg_length)
        write_into_log_db(message)

    elif command == "disconnect":
        msg = command
        msg_length, message = input_message(msg)
        sock.send(msg_length)
        sock.send(message)

        write_into_log_db(msg_length)
        write_into_log_db(message)

        sock.close()
        global connected
        connected = False
        print('\n[Disconnected] Successfully!')

    elif command == "upload":
        file_path = input(' > ')

        file_name = os.path.basename(file_path)
        file_name_length, file_name = input_message(file_name)
        sock.send(file_name_length)
        sock.send(file_name)

        file_len = os.path.getsize(file_path)
        print("file size:", file_len)
        sock.send(str(file_len).encode(ENCODING))

        write_into_log_db(file_name_length)
        write_into_log_db(file_name)
        write_into_log_db(str(file_len).encode(ENCODING))

        with open(file_path, 'rb') as f:  # Open in binary

            while True:
                sec = f.read(1024)
                if not sec:
                    break
                sock.sendall(sec)
                write_into_log_db(sec)

    elif command == "exec":
        cmd = input(" \> ")
        cmd_length, cmd = input_message(cmd)
        sock.send(cmd_length)
        sock.send(cmd)

        write_into_log_db(cmd_length)
        write_into_log_db(cmd)

        message_length = (sock.recv(MESSAGE_LENGTH_SIZE))
        write_into_log_db(message_length)

        msg = sock.recv(int(message_length.decode(ENCODING)))
        write_into_log_db(msg)

        print("[SERVER]:\n", msg.decode(ENCODING))

    elif command == "history":
        print("\n##Command History from Database:")
        records = "SELECT * FROM history "
        cursor.execute(records)
        for (record) in cursor:
            print(record[0], record[1])
        # f = open("cmd-history.txt", "r")  # Open in binary
        # print(f.read())
        # f.close()

    elif command == "log":
        print("\n##Packet Log from Database:")
        records = "SELECT * FROM log "
        cursor.execute(records)
        for (record) in cursor:
            print(record[0], record[1])

    elif command == "send-e":
        msg = input(" > ")
        msg_length, message = input_message(msg)

        hostname = 'example.org'
        ip = '127.0.0.1'
        port = 8443
        context = SSLContext(PROTOCOL_TLS_CLIENT)
        context.load_verify_locations('cert.pem')
        sleep(1)
        with create_connection((ip, port)) as client:
            with context.wrap_socket(client, server_hostname=hostname) as tls:
                tls.sendall(msg_length)
                tls.sendall(message)

                write_into_log_db(msg_length)
                write_into_log_db(msg)

                print(f'[SENT ENCRYPTED USING: {tls.version()}]')

                tls.close()
                client.close()

    else:
        print("Invalid Command. Try Again!")


def write_into_history_db(command):
    f = open("cmd-history.txt", "a")
    f.write("\n## " + command)
    f.close()

    cmd = (command,)
    add_record = "INSERT INTO history(command) VALUES(%s)"
    cursor.execute(add_record, cmd)
    conn.commit()


def write_into_log_db(data):
    dt = (data,)
    add_record = "INSERT INTO log(data) VALUES(%s)"
    cursor.execute(add_record, dt)
    conn.commit()


def input_message(msg):
    message = msg.encode(ENCODING)
    msg_length = len(message)
    msg_length = str(msg_length).encode(ENCODING)
    msg_length += b' ' * (MESSAGE_LENGTH_SIZE - len(msg_length))

    return msg_length, message


def find_open_ports(host, start_port, final_port):
    open_ports = []
    try:
        remote_ip = gethostbyname(host)
    except gaierror:
        print('Hostname could not be resolved. Exiting')
        sys.exit()

    for port in range(int(start_port), int(final_port) + 1):
        with socket() as s:
            s.settimeout(1)
            try:
                # print("Checking Port", port)
                s.connect((remote_ip, port))
                open_ports.append(port)
                print("{} accepted.".format(port))
            except:
                pass

    return open_ports


if __name__ == '__main__':
    # Database Connection
    conn = mysql.connector.connect(user='root', password='123456', host='localhost', database='CNdatabase')
    cursor = conn.cursor()
    # cursor.execute("drop table history")
    # cursor.execute("CREATE TABLE history (num INT AUTO_INCREMENT PRIMARY KEY, command VARCHAR(255))")

    # main function
    main()
    conn.close()
