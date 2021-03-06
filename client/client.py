import socket
import sys
import json
import logging

from file_factories import read_input_file, input_str_to_json, write_output
from csv_utilities import  write_output_to_csv
from client_factories import find_elm_list, find_differ_elm_list

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

if __name__ == '__main__':
    HOST = 'localhost'
    PORT = 5555
    INPUT_FILE = "../input/test_case_3.txt"

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

inputs = read_input_file(INPUT_FILE)
logger.debug(inputs)
mklist=[]
outputs = []
rules_installed = []
rules_removed = []
msid = ""
ratType = ""
for inp in inputs:
    if inp:
        objJSON = input_str_to_json(inp)
        json_input = json.loads(objJSON)
        action = json_input['action']

        if action == "start" and 'msid' in json_input:
            msid = json_input['msid']

        if 'at' in json_input:
            ratType = json_input['at']

        if mklist and action.upper() != "STOP":
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
  
        if msid:
            json_ans['msid'] = msid
        if ratType:
            json_ans['at'] = ratType
        outputs.append(json_ans)

        if 'monitoringKey' in json_ans:
            mklist=json_ans['monitoringKey']
        elif mklist:
            del mklist[:]
if outputs:
    logger.debug('Outputs: %s', outputs)
    write_output_to_csv(outputs)
