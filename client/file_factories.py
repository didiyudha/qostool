import string
import json
import sys
import logging
from datetime import datetime

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def read_input(file_name):
    contents = []
    if file_name:
        file_path = file_name
        # logger.debug('File name: %s', file_name)
        with open(file_path) as f:
            for line in f:
                line.strip()
                contents.append(line)
    return contents

def generate_file():
    dt = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    file_name = dt +".txt"
    arr_fname = string.split(file_name, " ")
    fname = str(arr_fname[0].replace("-", "") + "_" + str(arr_fname[1]).replace(":", ""))
    logger.debug("Generated text file: %s ", fname)
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
    cont = get_file_content(file_name)
    beforehand_data = cont + "\n"
    f = open(file_name, "w")
    f.write(str(beforehand_data))
    f.write(str(json_data)+"\n")
    f.close()

def arrange_output(json_output):
    output = ""
    if 'arp' in json_output:
        arp = json_output['arp']
        output +=str(arp)
    if 'qci' in json_output:
        qci = json_output['qci']
        output += str()
    if 'monitoringKey' in json_output:
        monitoringKey = json_output['monitoringKey']
        output += str(monitoringKey)
    if 'ruleInstall' in json_output:
        ruleInstall =json_output['ruleInstall']
        output += str(ruleInstall)
    if 'ruleRemoved' in json_output:
        ruleRemoved = json_output['ruleRemoved']
        output += str(ruleRemoved)
    if 'downlink' in json_output:
        downlink = json_output['downlink']
        output += str(downlink)
    if 'uplink' in json_output:
        uplink = json_output['uplink']
        output += str(uplink)
    if 'resultCode' in json_output:
        resultCode = json_output['resultCode']
        output += str(resultCode)
    output += "\n"
    return output

def write_output(file_name, json_data):
    logger.debug(file_name)
    logger.debug(json_data)
    cont = get_file_content(file_name)
    beforehand_data = cont + "\n"
    f = open(file_name, "w")
    f.write(str(beforehand_data))
    str_output = arrange_output(json_data)
    f.write(str_output+"\n")
    f.close()

def read_file(file_name):
    contents = []
    with open(file_name) as f:
        for line in f:
            logger.debug(line)
            contents.append(line)
    f.close()
    return contents

def read_input_file(file_name):
    contents = []
    try:
        with open(file_name) as lines:
            for line in lines:
                line.rstrip()
                line.replace('r', '')
                contents.append(line)
    except IOError as e:
        logger.error(e)
    return contents

def input_str_to_json(line_command):
    obj = {}
    if not line_command:
        return obj
    arr_line = str.split(line_command, ";")
    action = string.split(arr_line[0], "=")
    obj['action'] = action[1]
    logger.debug(line_command)
    if action and string.upper(action[1]) == "START":
        logger.info("Entering start command")
        logger.debug("arr_line: %s", arr_line)
        obj["msid"] = string.split(arr_line[1], "=")[1]
        if "apn" in str(line_command):
            obj["apn"] = string.split(arr_line[2], "=")[1]
        if "ip" in str(line_command):
            obj["ip"] = string.split(arr_line[3], "=")[1]
        if "at" in str(line_command):
            obj["at"] = string.split(arr_line[4], "=")[1]
    elif string.upper(action[1]) == "UPDATE" and "at" in str(line_command):
        obj["at"] = string.split(arr_line[1], "=")[1]
    json_obj = json.dumps(obj, sort_keys=True, indent=4, separators=(',', ': '))
    logger.debug(json_obj)
    return json_obj
