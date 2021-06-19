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
from pprint import pprint
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

#######################################################################################################


def usage():
    print("Usage: fmc_mass_log <FMC_address> <Policy_Name> [<VRF-Subnet.csv]")
    exit(0)


def generatetoken():
    print("Getting access token from FMC...")
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
            pprint(result.json())
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
                        print("Token expired, getting a new one")
                        Headers['X-auth-access-token'], domainUUID = generatetoken()
                        result = requests.put(ruleLink, headers=Headers, verify=False, data=json.dumps(ruleContent))
                    elif result.status_code == 429:
                        print("We hit the rate limiter, waiting...")
                        sleep(10)
                        Headers['X-auth-access-token'], domainUUID = generatetoken()
                        result = requests.put(ruleLink, headers=Headers, verify=False, data=json.dumps(ruleContent))
                    else:
                        pprint(result.json())
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
                        print("Token expired, getting a new one")
                        Headers['X-auth-access-token'], domainUUID = generatetoken()
                        result = requests.put(ruleLink, headers=Headers, verify=False, data=json.dumps(ruleContent))
                    elif result.status_code == 429:
                        print("We hit the rate limiter, waiting...")
                        sleep(10)
                        Headers['X-auth-access-token'], domainUUID = generatetoken()
                        result = requests.put(ruleLink, headers=Headers, verify=False, data=json.dumps(ruleContent))
                    else:
                        pprint(result.json())
                        exit(1)
                if result.json()['type'] == 'Host':
                    networks_result.append(ip_network(result.json()['value'] + '/32'))
                else:
                    networks_result.append(ip_network(result.json()['value']))
    return networks_result


def zone_find(rule_json, zone_dict):
    if not rule_json.get('destinationNetworks'):
        return None  # Destination is any
    dest_networks = get_networks(rule_json['destinationNetworks'])
    vrfs_set = set()
    found_networks = list()
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
    return None  # At least one network in a rule does not have a Zone


def isdenyipanyany(rule: dict)->bool:
    try:
        if rule['action'] == 'BLOCK' and  \
                (not rule.get('sourceNetworks') or rule['sourceNetworks']['objects'][0]['name'] == 'any') and \
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
        print(f'Parsing inputfile {file}')
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
            try:
                vrf_subnets[vrf].append(ip_network(subnet))
            except:
                try:
                    vrf_subnets[vrf].append(ip_interface(subnet).network)
                except:
                    print(f'Error parsing {file}')
                    print(f'{subnet} is not a valid subnet')
        print(f'Found {len(vrf_subnets)} security zones')
    return vrf_subnets


#######################################################################################################
# Main program starts here
#######################################################################################################


Headers = {'Content-Type': 'application/json'}
domainUUID = {}
findDestZones = False

if len(sys.argv) < 3:
    usage()

warnings.filterwarnings("ignore")
FMC = sys.argv[1]
Policy = sys.argv[2]

if len(sys.argv) == 4:
    VRF_Subnets = parse_csv(sys.argv[3])
    findDestZones = True

adminuser = input("Please enter admin username: ")
print("Please enter admin password: ", sep='')
adminpass = getpass(prompt='')

startTime = time()

# Get access token for FMC
Headers['X-auth-access-token'], domainUUID = generatetoken()


# Find policy to work with
print(f"Looking for policy {Policy}...")
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
    print(f"Policy with name {Policy} not found")
    exit(0)
print(f"Policy with name {Policy} found, id is {policyID}")


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
print(f'Found {len(rules)} rules')

# Get all zones if needed
if findDestZones:
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
            print(f'Security zone {item["name"]} has no networks defined')

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
            print("Token expired, getting a new one")
            Headers['X-auth-access-token'], domainUUID = generatetoken()
            result = requests.get(ruleLink, headers=Headers, verify=False)
        elif result.status_code == 429:
            print("We hit the rate limiter, waiting...")
            sleep(10)
            Headers['X-auth-access-token'], domainUUID = generatetoken()
            result = requests.get(ruleLink, headers=Headers, verify=False)
        else:
            pprint(f'Got error, status code is {result.status_code}')
            exit(1)
    ruleContent = result.json()

    if ruleContent.get('metadata'):  # Remove metadata or PUT will fail
        ruleContent.pop('metadata')

    if deleteDenyIPAnyAny and isdenyipanyany(ruleContent):  # Delete all "deny ip any any" rules
        print(f'Rule #{rule_counter} is "deny ip any any", deleting it')
        try:
            result = requests.delete(ruleLink, headers=Headers, verify=False)
            result.raise_for_status()
        except:
            if result.status_code == 401:
                print("Token expired, getting a new one")
                Headers['X-auth-access-token'], domainUUID = generatetoken()
                result = requests.delete(ruleLink, headers=Headers, verify=False)
            elif result.status_code == 429:
                print("We hit the rate limiter, waiting...")
                sleep(10)
                Headers['X-auth-access-token'], domainUUID = generatetoken()
                result = requests.delete(ruleLink, headers=Headers, verify=False)
            else:
                pprint(result.json())
                exit(1)
        continue

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

    if findDestZones:  # Find destination zones for a rule if needed
        destzones = zone_find(ruleContent, zones)
        if destzones:
            json_data = list()
            for next_seczone in destzones:
                json_data.append(zones[next_seczone]['json'])
            ruleContent['destinationZones'] = dict()
            ruleContent['destinationZones']['objects'] = json_data
            print(f'Rule #{rule_counter}, found {len(destzones)} destination zones')

    if ruleContent == oldContent:  # Maybe no need to change anything
        print(f'Rule #{rule_counter} ok, no changes needed')
        continue

    try:  # Apply changes
        result = requests.put(ruleLink, headers=Headers, verify=False, data=json.dumps(ruleContent))
        result.raise_for_status()
    except:
        if result.status_code == 401:
            print("Token expired, getting a new one")
            Headers['X-auth-access-token'], domainUUID = generatetoken()
            result = requests.put(ruleLink, headers=Headers, verify=False, data=json.dumps(ruleContent))
        elif result.status_code == 429:
            print("We hit the rate limiter, waiting...")
            sleep(10)
            Headers['X-auth-access-token'], domainUUID = generatetoken()
            result = requests.put(ruleLink, headers=Headers, verify=False, data=json.dumps(ruleContent))
        else:
            pprint(result.json())
            exit(1)
    print(f'Rule #{rule_counter} changed')

print(f"Operation took {time()-startTime} seconds")


