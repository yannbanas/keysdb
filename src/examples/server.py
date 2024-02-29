import threading
from keysdb import NetworkedKeyValueStore

def start_server():
    memdb = NetworkedKeyValueStore(host='localhost', port=4224, data_file='data.json')
    memdb.start()

if __name__ == "__main__":
    server_thread = threading.Thread(target=start_server)
    server_thread.start()
