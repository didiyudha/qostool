import string
import logging
import json
import csv
from datetime import datetime

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


def generate_file_name():
    dt = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    file_name = dt +".csv"
    arr_fname = string.split(file_name, " ")
    fname = str(arr_fname[0].replace("-", "") + "_" + str(arr_fname[1]).replace(":", ""))
    return fname

def parse_monitoring_key(mklist):
    keys = ""
    if not mklist:
        return ""
    for obj in mklist:
        for key in obj.keys():
            keys += str(key) + "|"
    return keys[:-1]

def parse_rule(rule_list):
    rules = ""
    if rule_list:
        for rule in rule_list:
            rules += rule + "|"
        return rules[:-1]
    return ""

def parse_obj_to_str(obj):
    if not obj:
        return ""
    output = ""
    if 'msisdn' in obj:
        output += obj['msisdn'] + ";"
    else:
        output += "-;"
    if 'at' in obj:
        output += obj['at'] + ";"
    else:
        output += "-;"
    if 'uplink' in obj:
        output += str(obj['uplink']) + ";"
    else:
        output += "-;"
    if 'downlink' in obj:
        output += str(obj['downlink']) + ";"
    else:
        output += "-;"

    if 'ruleInstall' in obj:
        ruleInstall = obj['ruleInstall']
        rules = parse_rule(ruleInstall)
        output += rules + ";"
    else:
        output += "-;"

    if 'ruleRemoved' in obj:
        rule_removed = obj['ruleRemoved']
        rmv = parse_rule(rule_removed)
        logger.debug('rule removed: %s', rmv)
        output += rmv + ";"
    else:
        output += "-;"

    if 'monitoringKey' in obj:
        mklist = obj['monitoringKey']
        str_mk = parse_monitoring_key(mklist)
        logger.debug('str_mk: %s', str_mk)
        output += str_mk + ";"
    else:
        output += "-;"

    if 'qci' in obj:
        output += str(obj['qci']) + ";"
    else:
        output += str(obj['arp']) + ";"

    if 'arp' in obj:
        output += str(obj['arp']) + ";"
    else:
         output += "-;"

    logger.debug('output: %s', output)
    return output[:-1]

def csv_writer(data, path):
    with open(path, "wb") as csv_file:
        writer = csv.writer(csv_file, delimiter=',')
        for line in data:
            writer.writerow(line)

def write_output(object_list):
    data = []
    header = "MSISDN;RATType;Uplink;Downlink;Rule Install;Rule Removed;Monitoring Key;QCI;ARP".split(";")
    data.append(header)
    output_obj = {}
    for obj in object_list:
        str_output = parse_obj_to_str(obj)
        output = str_output.split(";")
        logger.debug('output in write_output: %s', output)
        data.append(output)
    # logger.debug('data in write output: %s', data)
    file_name = generate_file_name()
    csv_writer(data, file_name)


if __name__ == '__main__':
    object_list = {}
    with open('json_out_example.json') as data_file:
        object_list = json.load(data_file)
    write_output(object_list)
    # logger.debug('output data: %s', data)