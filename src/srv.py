from keysdb import NetworkedKeyValueStore

memdb = NetworkedKeyValueStore(host='localhost', port=4224, data_file='data.json')
memdb.start()
