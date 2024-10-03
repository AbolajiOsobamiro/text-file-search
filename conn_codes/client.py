import socket
import configparser
import ssl

#reading the configuration file with configparser
config = configparser.ConfigParser()
config.read('configuration.ini')

#Initializing the connection constants
HEADER = int(config['client']['header'])
PORT = int(config['client']['port_number'])
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)
FORMAT = config['client']['format']
DISCONNECT_WORD = config['client']['disconnect_word']
CLIENT_CERT = config['client']['client_cert']
CLIENT_KEY = config['client']['client_key']
DISABLE_SSL = config.getboolean('general', 'disable_ssl')
ROOT_CERT = config['general']['root_cert']

#Initialize the client socket
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def connect_socket():
    """Connects to the server using SSL if 'DISABLE_SSL' is false, 
        otherwise, it connects using a plain socket connection.
    """

    try:
        client.connect(ADDR)
        print(f"[CLIENT] Connected to {ADDR}")

        if not DISABLE_SSL:
            context = ssl._create_unverified_context(ssl.PROTOCOL_TLS_CLIENT)
            context.load_cert_chain(CLIENT_CERT, CLIENT_KEY)
            context.load_verify_locations(ROOT_CERT)
            ssl_client = context.wrap_socket(client)
            print("[CLIENT] SSL is enabled...")
            return ssl_client
        else:
            print("[CLIENT] SSL is disabled")
            return client
        
    except Exception as e:
        print(f"[CLIENT] Error occurred during connection: {e}")
        return None


def send_message():
    """
    Allows the user to type a search string to send to the server
    and displays the server's response.
    Type 'quit' to disconnect.
    """
    conn = connect_socket()
    if conn:
        try:
            while True:
                msg = input("Enter a search string (or type 'quit' to exit): ")
                if msg == '':
                    continue

                message = msg.encode(FORMAT)

                conn.send(message)
            
                if msg.lower() == DISCONNECT_WORD:
                    break

                result = conn.recv(HEADER).decode(FORMAT) 
                print(f"{result}")

        except KeyboardInterrupt:    # When ctrl+c is pressed
            print("\n[CLIENT] Connection Interrupted. Disconnecting...")

        except ConnectionError as e:
            print(f"\n[CLIENT] Connection Error: {e}")

        except Exception as e:
            print(f"\n[CLIENT]An error occurred during message exchange: {e}")

        finally:
            conn.close()        #Closing the client connection
            print("[CLIENT] Disconnected. Goodbye.....")
    else:
        return 


send_message()          # Responds to the server's query