import requests
import sys
from getpass import getpass
import warnings
import json
from pprint import pprint
from time import time

desiredLog = {
    'logBegin': True,
    'logEnd': True,
    'sendEventsToFMC': False,
    'enableSyslog': True
}

Headers = {'Content-Type': 'application/json'}
domainUUID = {}


def usage():
    print("Usage: fmc_mass_log <FMC_address> <Policy_Name>")
    exit(0)


def generatetoken():
    print("Getting access token from FMC...")
    result = requests.post(f"https://{FMC}/api/fmc_platform/v1/auth/generatetoken",
                           auth=(adminuser, adminpass),
                           verify=False)
    try:
        result.raise_for_status()
    except:
        pprint(result.json())
        exit(1)
    token = result.headers['X-auth-access-token']
    domain = result.headers['DOMAIN_UUID']
    return token, domain


if len(sys.argv) != 3:
    usage()

warnings.filterwarnings("ignore")
FMC = sys.argv[1]
Policy = sys.argv[2]

adminuser = input("Please enter admin username: ")
print("Please enter admin password: ", sep='')
adminpass = getpass(prompt='')

startTime = time()

Headers['X-auth-access-token'], domainUUID = generatetoken()

print(f"Looking for policy {Policy}...")
result = requests.get(f'https://{FMC}/api/fmc_config/v1/domain/{domainUUID}/policy/accesspolicies',
                      headers=Headers,
                      verify=False)
policies = result.json()['items']
policyID = ''
for policy in policies:
    if policy['name'] == Policy:
        policyID = policy['id']
if not policyID:
    print(f"Policy with name {Policy} not found")
    exit(0)
print(f"Policy with name {Policy} found, id is {policyID}")

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
    rules.extend(result.json()['items'])

print(f'Found {len(rules)} rules')

rule_counter = 0
for rule in rules:
    rule_counter += 1
    ruleLink = rule['links']['self']
    result = requests.get(ruleLink, headers=Headers, verify=False)
    try:
        result.raise_for_status()
    except:
        if result.status_code == 401:
            print("Token expired, getting a new one")
            Headers['X-auth-access-token'], domainUUID = generatetoken()
            result = requests.get(ruleLink, headers=Headers, verify=False)
        else:
            pprint(f'Got error, status code is {result.status_code}')
            pprint(result.content)
            exit(1)
    ruleContent = result.json()
    if ruleContent.get('metadata'):
        ruleContent.pop('metadata')
    oldContent = ruleContent.copy()
    ruleContent.update(desiredLog)
    if ruleContent['action'] not in ['ALLOW', 'TRUST'] and ruleContent.get('logEnd'):  # Only ALLOW/TRUST supports LogEnd
        ruleContent.pop('logEnd')
    if ruleContent['action'] == 'MONITOR' and ruleContent.get('logBegin'):
        ruleContent.pop('logBegin')
    if ruleContent == oldContent:
        print(f'Rule #{rule_counter} ok, no changes needed')
        continue
    result = requests.put(ruleLink, headers=Headers, verify=False, data=json.dumps(ruleContent))
    try:
        result.raise_for_status()
    except:
        if result.status_code == 401:
            print("Token expired, getting a new one")
            Headers['X-auth-access-token'], domainUUID = generatetoken()
            result = requests.put(ruleLink, headers=Headers, verify=False, data=json.dumps(ruleContent))
        else:
            pprint(result.json())
            exit(1)
    print(f'Rule #{rule_counter} changed')

print(f"Operation took {time()-startTime} seconds")


