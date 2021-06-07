import requests
import sys
from getpass import getpass
import warnings


def usage():
    print("Usage: fmc_mass_log <FMC_address> <Policy_Name>")
    exit(0)


if len(sys.argv) != 3:
    usage()

warnings.filterwarnings("ignore")
FMC = sys.argv[1]
Policy = sys.argv[2]


print("Please enter admin username:")
adminuser = getpass()
print("Please enter admin password:")
adminpass = getpass()

print("Getting access token from FMC..")
result = requests.post(f"https://{FMC}/api/fmc_platform/v1/auth/generatetoken",
                      auth=(adminuser, adminpass),
                      verify=False)
result.raise_for_status()


Headers = {'X-auth-access-token': result.headers['X-auth-access-token']}
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

for rule in rules:
    print(rule)



