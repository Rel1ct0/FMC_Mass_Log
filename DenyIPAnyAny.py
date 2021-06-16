if __name__ == '__main__':
    print('Run fmc_mass_log.py instead')
    exit(1)


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
