import string
import json
import sys
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

from datetime import datetime

def generate_file():
    dt = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    file_name = dt +".txt"
    arr_fname = string.split(file_name, " ")
    fname = str(arr_fname[0]) + "-" + str(arr_fname[1]).replace(":", "-")
    open(fname, 'w').close()
    return fname

def get_file_content(file_name):
    f = open(file_name, "r")
    content = f.read(1024)
    logger.debug('content: %s', content)
    f.close()
    return content

def write_file(file_name, json_data):
    logger.debug(file_name)
    logger.debug(json_data)
    # action, msid, apn, ip, at = extract_json_input()
    cont = get_file_content(file_name)
    beforehand_data = cont + "\n"
    f = open(file_name, "w")
    f.write(str(beforehand_data))
    f.write(str(json_data)+"\n")
    f.close()
