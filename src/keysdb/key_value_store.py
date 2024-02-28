import collections
import time
import json
import logging
from threading import Lock
from .exceptions import KeyNotFoundError, DataTypeError, InvalidDataType

logger = logging.getLogger(__name__)

class KeyValueStore:
    SUPPORTED_DATA_TYPES = ['string', 'integer', 'list', 'hash']

    def __init__(self, data_file='data.json', ttl=None):
        self.data = collections.OrderedDict()
        self.data_file = data_file
        self.ttl = ttl
        self.lock = Lock()

        # Load data from file if it exists
        try:
            with open(data_file, 'r') as f:
                self.data = collections.OrderedDict(json.load(f))
        except FileNotFoundError:
            pass
        except json.JSONDecodeError as e:
            logger.error(f"Error loading data from file: {e}")
            self.data = collections.OrderedDict()

    def _save_data(self):
        try:
            with open(self.data_file, 'w') as f:
                json.dump(list(self.data.items()), f)
        except Exception as e:
            logger.error(f"Error saving data to file: {e}")

    def set(self, key, value, data_type='string', ttl=None):
        """
        Set a value in the key-value store.

        :param key: The key to set.
        :param value: The value to set.
        :param data_type: The data type of the value (string, integer, list, or hash).
        :param ttl: Time-to-live for the key-value pair in seconds.
        """
        with self.lock:
            if data_type not in self.SUPPORTED_DATA_TYPES:
                raise InvalidDataType(f"Invalid data type: {data_type}")

            if ttl is None:
                ttl = self.ttl if self.ttl is not None else 0

            if data_type == 'integer':
                try:
                    value = int(value)
                except ValueError:
                    raise DataTypeError("Value is not an integer")

            self.data[key] = {'value': value, 'data_type': data_type, 'expires': time.time() + ttl}
            self._save_data()

    def set_hash(self, key, field, value, ttl=None):
        if key not in self.data:
            self.data[key] = {'value': {}, 'data_type': 'hash', 'expires': time.time() + (ttl if ttl is not None else 0)}

        if field in self.data[key]['value']:
            self.data[key]['value'][field] = value
        else:
            self.data[key]['value'][field] = value

        self._save_data()

    def get_hash(self, key, field):
        if key not in self.data:
            raise KeyNotFoundError(f"Key '{key}' not found")

        if time.time() > self.data[key]['expires']:
            del self.data[key]
            self._save_data()
            raise KeyNotFoundError(f"Key '{key}' has expired")

        if field not in self.data[key]['value']:
            raise KeyNotFoundError(f"Field '{field}' not found in key '{key}'")

        return self.data[key]['value'][field]

    def get(self, key):
        """
        Get a value from the key-value store.

        :param key: The key to get.
        :return: The value associated with the key, or None if the key is not found.
        :raises KeyNotFoundError: If the key is not found and raise_error is True.
        """
        with self.lock:
            if key not in self.data:
                raise KeyNotFoundError(f"Key '{key}' not found")

            # Check if the key has expired
            if time.time() > self.data[key]['expires']:
                del self.data[key]
                self._save_data()
                raise KeyNotFoundError(f"Key '{key}' has expired")

            return self.data[key]['value']

    def delete(self, key):
        """
        Delete a key-value pair from the key-value store.

        :param key: The key to delete.
        """
        with self.lock:
            if key in self.data:
                del self.data[key]
                self._save_data()

    def clear(self):
        """
        Clear all key-value pairs from the store.
        """
        with self.lock:
            self.data.clear()
            self._save_data()

    def __contains__(self, key):
        """
        Check if a key exists in the key-value store.

        :param key: The key to check.
        :return: True if the key exists, False otherwise.
        """
        with self.lock:
            return key in self.data

    def __iter__(self):
        """
        Iterate over the keys in the key-value store.

        :return: An iterator over the keys.
        """
        with self.lock:
            return iter(self.data)

    def __len__(self):
        """
        Get the number of key-value pairs in the key-value store.

        :return: The number of key-value pairs.
        """
        with self.lock:
            return len(self.data)
