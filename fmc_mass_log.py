import requests
import sys
from getpass import getpass
import warnings
from pprint import pprint
import json

desiredLog = {
    'logBegin': True,
    'logEnd': True,
    'sendEventsToFMC': False,
    'enableSyslog': True
}


def usage():
    print("Usage: fmc_mass_log <FMC_address> <Policy_Name>")
    exit(0)


if len(sys.argv) != 3:
    usage()

warnings.filterwarnings("ignore")
FMC = sys.argv[1]
Policy = sys.argv[2]

adminuser = input("Please enter admin username: ")
print("Please enter admin password: ", sep='')
adminpass = getpass(prompt='')

print("Getting access token from FMC..")
result = requests.post(f"https://{FMC}/api/fmc_platform/v1/auth/generatetoken",
                      auth=(adminuser, adminpass),
                      verify=False)
result.raise_for_status()


Headers = {'X-auth-access-token': result.headers['X-auth-access-token'],
           'Content-Type': 'application/json'}
domainUUID = result.headers['DOMAIN_UUID']

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

result = requests.get(f'https://{FMC}/api/fmc_config/v1/domain/{domainUUID}/policy/accesspolicies/{policyID}/accessrules',
                      headers=Headers,
                      verify=False)
rules = result.json()['items']
print(f'Found {len(rules)} rules')

rule_counter = 0
for rule in rules:
    ruleLink = rule['links']['self']
    ruleContent = requests.get(ruleLink, headers=Headers, verify=False).json()
    ruleContent.pop('metadata')
    result = requests.put(ruleLink, headers=Headers, verify=False, data=json.dumps(ruleContent))
    result.raise_for_status()
    rule_counter += 1
    print(f'Rule #{rule_counter} changed')


