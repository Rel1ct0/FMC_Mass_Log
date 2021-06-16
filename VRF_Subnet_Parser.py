if __name__ == '__main__':
    print('Run fmc_mass_log.py instead')
    exit(1)


from csv import reader


def parse_csv(file):
    with open(file, encoding="utf-8-sig") as inputfile:
        print(f'Parsing inputfile {file}')
        vrf_subnets = dict()
        content = reader(inputfile, delimiter=';')
        for nextline in content:
            print(nextline)
            vrf, subnet = nextline
            if subnet.find('/') == -1:
                subnet = subnet + '/24'
            if not vrf_subnets.get(vrf):  # New VRF
                vrf_subnets[vrf] = list()
            vrf_subnets[vrf].append(subnet)
    return vrf_subnets

