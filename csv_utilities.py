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
    logger.debug('mklist: %s', mklist)
    for obj in mklist:
        logger.debug(obj)
        for key in obj.keys():
            logger.debug(key)
            keys += str(key) + ","
    return keys[:-1]

def parse_rule(rule_list):
    rules = ""
    if rule_list:
        for rule in rule_list:
            rules += rule + ","
        return rules[:-1]
    return ""

def write_output(object_list, msid):
    data = []
    header = "Uplink,Downlink,Rule Install,Monitoring Key,Rule Removed,QCI,ARP".split(",")
    data.append(header)
    output_obj = {}
    for obj in object_list:
        logger.debug(obj)

if __name__ == '__main__':
    result = {}
    result['monitoringKey'] = [{"5157": 10485760}, {"5156": 10485760}]
    result['ruleInstall'] = ["1", "157"]
    mk = result['monitoringKey']
    ruleInstall = result['ruleInstall']
    logger.debug(mk)
    parse_mk = parse_monitoring_key(mk)
    logger.debug(parse_mk)
    parse_rule = parse_rule(ruleInstall)
    logger.debug(parse_rule)






