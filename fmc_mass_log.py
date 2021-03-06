"""
Script to find all rules in the Access Control Policy and change them
See desiredState variable below
You can also specify CSV-file with SecurityZone;Subnet columns, script will try
to find and specify destination zones in the rule
Script will also delete 'deny ip any any' rules by default
"""

import requests
import sys
from getpass import getpass
import warnings
import json
from time import time, sleep
from ipaddress import ip_network, ip_interface
from csv import reader


#######################################################################################################
# Variables block

desiredState = {
    'logBegin': True,
    'logEnd': True,
    'sendEventsToFMC': False,
    'enableSyslog': True
}

changeAllowToTrust = True
deleteDenyIPAnyAny = True
defaultZone = ''
logfile = 'fmc_mass_log.log'
logfile_fd = ''

#######################################################################################################


def usage():
    print("Usage: fmc_mass_log <FMC_address> <Policy_Name> [<VRF-Subnet.csv> [<Default-Zone-Name]]")
    exit(0)


def zprint(text):
    global logfile_fd
    print(text)
    if logfile_fd:
        logfile_fd.write(text + '\n')
    return


def generatetoken():
    zprint("Getting access token from FMC...")
    result = requests.post(f"https://{FMC}/api/fmc_platform/v1/auth/generatetoken",
                           auth=(adminuser, adminpass),
                           verify=False)
    try:
        result.raise_for_status()
    except:
        if result.status_code == 429:
            sleep(10)
            result = requests.post(f"https://{FMC}/api/fmc_platform/v1/auth/generatetoken",
                                   auth=(adminuser, adminpass),
                                   verify=False)
        else:
            zprint(result.json())
            exit(1)
    token = result.headers['X-auth-access-token']
    domain = result.headers['DOMAIN_UUID']
    return token, domain


def get_networks(dest: dict):
    global FMC
    global domainUUID
    global Headers
    networks_result = list()
    if dest.get('literals'):
        for literal in dest['literals']:
            if literal['type'] == "Host":
                networks_result.append(ip_network(literal['value'] + '/32'))
            else:
                networks_result.append(ip_network(literal['value']))
    if dest.get('objects'):
        for next_object in dest['objects']:
            if next_object['type'] == 'NetworkGroup':  # Must get content of Network Group
                try:
                    result = requests.get(
                        f'https://{FMC}/api/fmc_config/v1/domain/{domainUUID}/object/networkgroups/{next_object["id"]}',
                        headers=Headers, verify=False)
                    result.raise_for_status()
                except:
                    if result.status_code == 401:
                        zprint("Token expired, getting a new one")
                        Headers['X-auth-access-token'], domainUUID = generatetoken()
                        result = requests.put(ruleLink, headers=Headers, verify=False, data=json.dumps(ruleContent))
                    elif result.status_code == 429:
                        zprint("We hit the rate limiter, waiting...")
                        sleep(10)
                        Headers['X-auth-access-token'], domainUUID = generatetoken()
                        result = requests.put(ruleLink, headers=Headers, verify=False, data=json.dumps(ruleContent))
                    else:
                        zprint(result.json())
                        exit(1)
                networks_result.extend(get_networks(result.json()))
            elif next_object['type'] == 'Network':
                try:
                    result = requests.get(
                        f'https://{FMC}/api/fmc_config/v1/domain/{domainUUID}/object/networks/{next_object["id"]}',
                        headers=Headers, verify=False)
                    result.raise_for_status()
                except:
                    if result.status_code == 401:
                        zprint("Token expired, getting a new one")
                        Headers['X-auth-access-token'], domainUUID = generatetoken()
                        result = requests.put(ruleLink, headers=Headers, verify=False, data=json.dumps(ruleContent))
                    elif result.status_code == 429:
                        zprint("We hit the rate limiter, waiting...")
                        sleep(10)
                        Headers['X-auth-access-token'], domainUUID = generatetoken()
                        result = requests.put(ruleLink, headers=Headers, verify=False, data=json.dumps(ruleContent))
                    else:
                        zprint(result.json())
                        exit(1)
                if result.json()['type'] == 'Host':
                    networks_result.append(ip_network(result.json()['value'] + '/32'))
                else:
                    networks_result.append(ip_network(result.json()['value']))
    return networks_result


def zone_find(rule_json, zone_dict):
    vrfs_set = set()
    found_networks = list()
    dest_networks = ['dummy_data']
    if rule_json.get('destinationNetworks'):
        dest_networks = get_networks(rule_json['destinationNetworks'])
        for net in dest_networks:
            not_found = True
            for zone in zone_dict.keys():
                if zone_dict[zone].get('networks'):
                    for zone_net in zone_dict[zone]['networks']:
                        try:
                            if net.subnet_of(zone_net):
                                if not_found:  # First Zone found for this network
                                    found_networks.append(net)
                                not_found = False  # If we find more Zones for this network, still counts as one network
                                vrfs_set.add(zone)
                        except:
                            pass
    if len(dest_networks) == len(found_networks):  # At least one Zone found for every network in rule
        result = list(vrfs_set)
        result.sort()
        return result
    elif defaultZone:  # Some networks not identified, assuming they belong to default Zone
        vrfs_set.add(defaultZone)
        result = list(vrfs_set)
        result.sort()
        return result
    return None  # At least one network in a rule does not have a Zone, and no default Zone specified


def zone_find_src(rule_json, zone_dict):
    vrfs_set = set()
    found_networks = list()
    src_networks = ['dummy_data']
    if rule_json.get('sourceNetworks'):
        src_networks = get_networks(rule_json['sourceNetworks'])
        for net in src_networks:
            not_found = True
            for zone in zone_dict.keys():
                if zone_dict[zone].get('networks'):
                    for zone_net in zone_dict[zone]['networks']:
                        try:
                            if net.subnet_of(zone_net):
                                if not_found:  # First Zone found for this network
                                    found_networks.append(net)
                                not_found = False  # If we find more Zones for this network, still counts as one network
                                vrfs_set.add(zone)
                        except:
                            pass
    if len(src_networks) == len(found_networks):  # At least one Zone found for every network in rule
        result = list(vrfs_set)
        result.sort()
        return result
    elif defaultZone:  # Some networks not identified, assuming they belong to default Zone
        vrfs_set.add(defaultZone)
        result = list(vrfs_set)
        result.sort()
        return result
    return None  # At least one network in a rule does not have a Zone, and no default Zone specified


def isipanyany(rule: dict) -> bool:
    try:
        if (not rule.get('sourceNetworks') or rule['sourceNetworks']['objects'][0]['name'] == 'any') and \
                (not rule.get('destinationNetworks') or rule['destinationNetworks']['objects'][0]['name'] == 'any') and \
                not rule.get('sourcePorts') and \
                not rule.get('urls') and \
                not rule.get('destinationPorts') and \
                not rule.get('applications'):
            return True
    except:
        pass
    return False


def parse_csv(file):
    with open(file, encoding="utf-8-sig") as inputfile:
        zprint(f'Parsing inputfile {file}')
        vrf_subnets = dict()
        content = reader(inputfile, delimiter=';')
        for nextline in content:
            vrf, subnet = nextline
            vrf = vrf.strip()
            subnet = subnet.strip()
            if subnet.find('/') == -1:
                subnet = subnet + '/24'
            if not vrf_subnets.get(vrf):  # New VRF
                vrf_subnets[vrf] = list()
            try:  # Is that a network address?
                vrf_subnets[vrf].append(ip_network(subnet))
            except:
                try:  # Not a network address. Maybe an interface address?
                    vrf_subnets[vrf].append(ip_interface(subnet).network)
                except:  # Not an interface address. Skipping.
                    zprint(f'Error parsing {file}')
                    zprint(f'{subnet} is not a valid subnet')
        zprint(f'Found {len(vrf_subnets)} security zones')
    return vrf_subnets


#######################################################################################################
# Main program starts here
#######################################################################################################


Headers = {'Content-Type': 'application/json'}
domainUUID = {}
Zone_CSV_Present = False
permitAnyAnyRules = list()

if len(sys.argv) < 3:
    usage()

warnings.filterwarnings("ignore")
FMC = sys.argv[1]
Policy = sys.argv[2]

if len(sys.argv) > 3:
    VRF_Subnets = parse_csv(sys.argv[3])
    Zone_CSV_Present = True
    if len(sys.argv) == 5:
        defaultZone = sys.argv[4]

if logfile:
    logfile_fd = open(logfile, 'w')

adminuser = input("Please enter admin username: ")
print("Please enter admin password: ", sep='')
adminpass = getpass(prompt='')

startTime = time()

# Get access token for FMC
Headers['X-auth-access-token'], domainUUID = generatetoken()


# Find policy to work with
zprint(f"Looking for policy {Policy}...")
result = requests.get(f'https://{FMC}/api/fmc_config/v1/domain/{domainUUID}/policy/accesspolicies',
                      headers=Headers,
                      verify=False)
result.raise_for_status()
policies = result.json()['items']
policyID = ''
for policy in policies:
    if policy['name'] == Policy:
        policyID = policy['id']
if not policyID:
    zprint(f"Policy with name {Policy} not found")
    exit(0)
zprint(f"Policy with name {Policy} found, id is {policyID}")


# Get all rules from the policy
result = requests.get(
    f'https://{FMC}/api/fmc_config/v1/domain/{domainUUID}/policy/accesspolicies/{policyID}/accessrules?offset=0&limit=1000',
    headers=Headers,
    verify=False)
rules = result.json()['items']
while result.json()['paging'].get('next'):
    result = requests.get(
        result.json()['paging'].get('next')[0],
        headers=Headers,
        verify=False)
    result.raise_for_status()
    rules.extend(result.json()['items'])
zprint(f'Found {len(rules)} rules')

# Get all zones if needed
if Zone_CSV_Present:
    result = requests.get(
        f'https://{FMC}/api/fmc_config/v1/domain/{domainUUID}/object/securityzones?offset=0&limit=1000',
        headers=Headers,
        verify=False)
    result.raise_for_status()
    raw_zones = result.json()['items']
    zones = dict()
    for item in raw_zones:
        zones[item['name']] = dict()
        zones[item['name']]['json'] = item
        zones[item['name']]['json'].pop('links')
        if VRF_Subnets.get(item['name']):
            zones[item['name']]['networks'] = VRF_Subnets[item['name']]
        else:
            zprint(f'Security zone {item["name"]} has no networks defined')

# Main loop
rule_counter = 0
for rule in rules:
    rule_counter += 1
    ruleLink = rule['links']['self']

    try:  # Get rule content
        result = requests.get(ruleLink, headers=Headers, verify=False)
        result.raise_for_status()
    except:
        if result.status_code == 401:
            zprint("Token expired, getting a new one")
            Headers['X-auth-access-token'], domainUUID = generatetoken()
            result = requests.get(ruleLink, headers=Headers, verify=False)
        elif result.status_code == 429:
            zprint("We hit the rate limiter, waiting...")
            sleep(10)
            Headers['X-auth-access-token'], domainUUID = generatetoken()
            result = requests.get(ruleLink, headers=Headers, verify=False)
        else:
            zprint(f'Got error, status code is {result.status_code}')
            exit(1)
    ruleContent = result.json()

    if ruleContent.get('metadata'):  # Remove metadata or PUT will fail
        ruleContent.pop('metadata')

    # Delete all "deny ip any any" rules
    if deleteDenyIPAnyAny and ruleContent['action'] == 'BLOCK' and isipanyany(ruleContent):
        zprint(f'Rule #{rule_counter} is "deny ip any any", deleting it')
        try:
            result = requests.delete(ruleLink, headers=Headers, verify=False)
            result.raise_for_status()
        except:
            if result.status_code == 401:
                zprint("Token expired, getting a new one")
                Headers['X-auth-access-token'], domainUUID = generatetoken()
                result = requests.delete(ruleLink, headers=Headers, verify=False)
            elif result.status_code == 429:
                zprint("We hit the rate limiter, waiting...")
                sleep(10)
                Headers['X-auth-access-token'], domainUUID = generatetoken()
                result = requests.delete(ruleLink, headers=Headers, verify=False)
            else:
                zprint(result.json())
                exit(1)
        continue

    if ruleContent['action'] in ['ALLOW', 'TRUST'] and isipanyany(ruleContent):
        permitAnyAnyRules.append(ruleContent['name'])

    oldContent = ruleContent.copy()
    ruleContent.update(desiredState)

    if changeAllowToTrust:  # Must remove IPS, File Policy and Variable set from TRUST rules
        if ruleContent['action'] == 'ALLOW':
            ruleContent['action'] = 'TRUST'
            if ruleContent.get('ipsPolicy'):
                ruleContent.pop('ipsPolicy')
            if ruleContent.get('variableSet'):
                ruleContent.pop('variableSet')
            if ruleContent.get('filePolicy'):
                ruleContent.pop('filePolicy')

    if ruleContent['action'] not in ['ALLOW', 'TRUST'] and ruleContent.get('logEnd'):  # Only ALLOW/TRUST supports LogEnd
        ruleContent['logEnd'] = False
    if ruleContent['action'] == 'MONITOR' and ruleContent.get('logBegin'):
        ruleContent['logBegin'] = False

    if Zone_CSV_Present:  # Find destination zones for a rule if needed
        destzones = zone_find(ruleContent, zones)
        if destzones:
            json_data = list()
            for next_seczone in destzones:
                json_data.append(zones[next_seczone]['json'])
            ruleContent['destinationZones'] = dict()
            ruleContent['destinationZones']['objects'] = json_data
            zprint(f'Rule #{rule_counter}, found {len(destzones)} destination zones')

    if Zone_CSV_Present and \
        defaultZone and \
            ruleContent.get('sourceZones') and \
            ruleContent['sourceZones']['objects'][0]['name'] == defaultZone and \
            len(ruleContent['sourceZones']['objects']) == 1:  # Find source zones for a rule if needed
        srczones = zone_find_src(ruleContent, zones)
        if srczones:
            json_data = list()
            for next_seczone in srczones:
                json_data.append(zones[next_seczone]['json'])
            ruleContent['sourceZones'] = dict()
            ruleContent['sourceZones']['objects'] = json_data
            zprint(f'Rule #{rule_counter}, found {len(srczones)} source zones')

    if ruleContent == oldContent:  # Maybe no need to change anything
        zprint(f'Rule #{rule_counter} ({ruleContent["name"]}) ok, no changes needed')
        continue

    try:  # Apply changes
        result = requests.put(ruleLink, headers=Headers, verify=False, data=json.dumps(ruleContent))
        result.raise_for_status()
    except:
        if result.status_code == 401:
            zprint("Token expired, getting a new one")
            Headers['X-auth-access-token'], domainUUID = generatetoken()
            result = requests.put(ruleLink, headers=Headers, verify=False, data=json.dumps(ruleContent))
        elif result.status_code == 429:
            zprint("We hit the rate limiter, waiting...")
            sleep(10)
            Headers['X-auth-access-token'], domainUUID = generatetoken()
            result = requests.put(ruleLink, headers=Headers, verify=False, data=json.dumps(ruleContent))
        else:
            zprint(result.json())
            exit(1)
    zprint(f'Rule #{rule_counter} ({ruleContent["name"]}) changed')

zprint(f"Operation took {time()-startTime} seconds")

if permitAnyAnyRules:
    for rule in permitAnyAnyRules:
        zprint(f'Warning, rule {rule} is "permit ip any any"')

if logfile_fd:
    logfile_fd.close()
