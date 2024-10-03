import socket
import threading
import configparser
import logging
import ssl
import mmap
import time

# Reading the configuration file with configparser
config = configparser.ConfigParser()
config.read('configuration.ini')

# Implementing logging functionality and defining the logging format
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(message)s', datefmt='%H:%M:%S')

#Initializing the connection constants
HEADER = int(config['server']['header'])
PORT = int(config['server']['port_number'])
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)
FORMAT = config['server']['format']
DISCONNECT_WORD = config['server']['disconnect_word']
REREAD_ON_QUERY = config['server'].getboolean('reread_on_query')
DISABLE_SSL = config.getboolean('general', 'disable_ssl')
SERVER_CERT = config['server']['server_cert']
SERVER_KEY = config['server']['server_key']
file_path = config['server']['linuxpath']


original_content = None
content_lock = threading.Lock()

# Creating a server socket that accepts connections
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(ADDR)


def load_file(path):
    """
    Loads the file content from the specified path into memory.
    """
    global original_content
    try:
        with open(path, 'rb') as text_file:
            #original_content = text_file.readlines()
            original_content = mmap.mmap(text_file.fileno(), 0, prot=mmap.PROT_READ)
    except FileNotFoundError:
        original_content = None
        logging.error(f"[ERROR] File not found : {path}")

    
def search_file(path, searched_string):
    """
    Searches for the given string in the file.
    Returns:
        str: "STRING EXISTS" if the string is found, otherwise "STRING NOT FOUND".
    """

    try:
        if REREAD_ON_QUERY:
            with open(path, 'rb') as text_file:
                content = mmap.mmap(text_file.fileno(), 0, prot=mmap.PROT_READ)
                
        else:
            global original_content
            with content_lock:
                if original_content is None:
                    load_file(file_path)
                content = original_content


        searched_string = searched_string.encode()
        content.seek(0)
        for line in iter(content.readline, b''):
            if line.strip() == searched_string:
                return "STRING EXISTS\n"
            
        else:
                return "STRING NOT FOUND\n"


    except FileNotFoundError:
        return "File not Found"


def handle_connections(conn, addr):
    """
    Handles the client's connection, receives search queries, and sends responses.

    Args:
        conn: The connection object for the client.
        addr: The client's address (IP, port).
    """
    logging.info(f"[NEW CONNECTION] {addr} connected")
    
    try:
        while True:
            search_string = conn.recv(HEADER).decode(FORMAT).strip()
            if not search_string:  
                break

            if len(search_string) > HEADER:
                conn.send("ERROR: Payload too large\n".encode())
                continue

            if search_string == DISCONNECT_WORD:
                logging.info(f"[{addr}] is disconnecting")
                break

            
            logging.info(f"[{addr}] is searching for '{search_string}'")
            start = time.time()
            result = search_file(file_path, search_string)
            conn.send(f"{search_string} : {result}".encode(FORMAT))
            stop = time.time()
            time_taken = stop - start

            logging.debug(f"DEBUG: Search query executed in {time_taken:.4f} seconds")
    except Exception as e:
        logging.error(f"Error with client {addr}: {e}")

    finally:
        conn.close()
        logging.info(f"[CONNECTION CLOSED] {addr} disconnected")


def start_server():
    """
    Starts the server and begins accepting connections.
    Configures SSL if not disabled in the configuration.
    """
    server.listen()
    logging.info(f"[LISTENING] Server is listening on {SERVER}")

    if DISABLE_SSL:
        ssl_server = server
        logging.info("[SERVER] SSL is Disabled")
    else:
        logging.info("[SERVER] SSL is enabled")
        try:
            context = ssl._create_unverified_context(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(SERVER_CERT, SERVER_KEY)
            ssl_server = context.wrap_socket(server, server_side=True)
        except ssl.SSLError as e:
            logging.error(f"[ERROR] SSL setup failed: {e}")
            return 


    try:
        while True:
            conn, addr = ssl_server.accept()
            logging.info(f"Accepted secure connection from {addr}")

            thread = threading.Thread(target=handle_connections, args=(conn, addr))
            thread.start()
            logging.info(f"[ACTIVE CONNECTIONS] {threading.active_count()-1}")
    
    except KeyboardInterrupt:
        logging.warning("\n[SERVER] Connection Interrupted. Closing Server....")


    finally:
        ssl_server.close()


logging.debug("[STARTING] server is starting.....")
start_server()
