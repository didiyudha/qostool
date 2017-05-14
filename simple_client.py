import socket
import sys
import logging
import json
from pkgutil import simplegeneric

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

from file_factories import read_file



if __name__ == '__main__':
	PORT = 5000
	HOST = 'localhost'
        file_name = "test.txt"
	client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            logger.info('Socket was created successfully')
            client_socket.connect((HOST, PORT))
        except:
            logger.error('Can not connect to HOST %s and PORT %s', HOST, PORT)
            sys.exit()
        logger.info('Connection is successfully established')
        contents = read_file(file_name)
        for msg in contents:
            try:
                client_socket.sendall(msg)
            except socket.error:
                logger.error('Can not send data to server')
                sys.exit()
            answer = client_socket.recv(4096)
            logger.debug('Answer: %s', answer)
