from keysdb import *

import logging.config

logging_config = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'standard',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
}

logging.config.dictConfig(logging_config)

# Usage example
store = KeyValueStore(ttl=3600)  # Set a default TTL of 1 hour

# Set key-value pairs
store.set("name", "John Doe")
store.set("age", 30)
store.set("favorite_numbers", [1, 2, 3, 4, 5], data_type='list')
store.set("address", {"city": "New York", "country": "USA"}, data_type='hash')

# Get values
try:
    print(store.get("name"))  # Output: John Doe
except KeyNotFoundError as e:
    print(e)

try:
    print(store.get("unknown_key"))
except KeyNotFoundError as e:
    print(e)  # Output: Key 'unknown_key' not found

# Delete a key-value pair
store.delete("age")

# Check if keys exist in the store
if "name" in store:
    print("Name exists in the store")

if "age" not in store:
    print("Age does not exist in the store")

# Iterate over the keys in the store
for key in store:
    print(key, store.get(key))

# Get the number of key-value pairs in the store
print("Number of key-value pairs in the store:", len(store))

# Clear all key-value pairs in the store
store.clear()

# Verify that the store is empty
if not store:
    print("The store is empty")
