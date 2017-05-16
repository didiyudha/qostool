import socket
import sys
import json
import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def read_input(file_name):
    contents = []
    if file_name:
        file_path = file_name
        logger.debug('File name: %s', file_name)
        with open(file_path) as f:
            for line in f:
                line.strip()
                contents.append(line)
    return contents

if __name__ == '__main__':
	HOST = 'localhost'
	PORT = 5555
	FILE_NAME = "input.txt"
try:
	client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error:
	logger.error('Can not create socket')
	sys.exit()
try:
	client_socket.connect((HOST, PORT))
except socket.error:
	logger.error('Can connect to HOST: %s and PORT: %s', HOST, PORT)
logger.info('Connection was established successfully')

inputs = read_input(FILE_NAME)
mklist = []
for inp in inputs:
    if inp:
        json_input = json.loads(inp)
        logger.debug(json_input)
        if mklist:
            json_input['mk'] = mklist
        try:
	    logger.debug('send command to server: %s', json_input)
	    cmd = json.dumps(json_input).encode('utf-8')
            client_socket.sendall(cmd)
        except socket.error:
            logger.info('Failed sending message to the server')
            sys.exit()
        ans = client_socket.recv(1024)
        json_ans = json.loads(ans)
        if 'monitoringKey' in json_ans:
	    mklist = json_ans['monitoringKey']

