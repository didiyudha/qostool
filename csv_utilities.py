import string
import logging
from datetime import datetime

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


def generate_file():
    dt = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    file_name = dt +".csv"
    arr_fname = string.split(file_name, " ")
    fname = str(arr_fname[0].replace("-", "") + "_" + str(arr_fname[1]).replace(":", ""))
    logger.debug("Generated text file: %s ", fname)
    open(fname, 'w').close()
    return fname

def parse_monitoring_key(mklist):
    keys = ""
    if not mklist:
        return ""
    for mk in mklist:
        for key, value in mk:
            # key as monitoring key and value as QoS slice value
            monitoring_key = key
            qos_slice_value = str(value)
            keys += monitoring_key + ","
    return keys

def parse_rule(rules):
    if rules == "" or rules == "-":
        return ""
    values = ""
    for s in rules:
        values += s + ","
    return values


def write_output(object_list, msid):
    data = []
    header = "Uplink,Downlink,Rule Install,Monitoring Key,Rule Removed,QCI,ARP".split(",")
    data.append(header)
    output_obj = {}
    for obj in object_list:
        output_obj['uplink'] = obj['uplink'] if 'uplink' in obj else output_obj['uplink'] = "-"
        output_obj['downlink'] = obj['downlink'] if 'downlink' in obj else output_obj['uplink'] = "-"
        output_obj['ruleInstall'] = obj['ruleInstall'] if 'ruleInstall' in obj else output_obj['ruleInstall'] = "-"
        output_obj['monitoringKey'] = obj['monitoringKey'] if 'monitoringKey' in obj else output_obj['monitoringKey'] = "-"
        output_obj['ruleRemoved'] = obj['ruleRemoved'] if 'ruleRemoved' in obj else output_obj['ruleRemoved'] = "-"
        output_obj['qci'] = obj['qci'] if 'qci' in obj else output_obj['qci'] = "-"
        output_obj['arp'] = obj['arp'] if 'arp' in obj else output_obj['arp'] = "-"

        parsed_mk = parse_monitoring_key(output_obj['monitoringKey'])
        rule_install = parse_rule(output_obj['ruleInstall'])
        rule_removed = parse_rule(output_obj['ruleInstall'])

        data = (output_obj['uplink']+","+output_obj['downlink']+","+rule_install+
                parsed_mk+rule_removed+output_obj['qci']+","+output_obj['arp'])
        logger.debug(data)



