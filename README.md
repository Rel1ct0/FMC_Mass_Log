# FMC_Mass_Log

Script to find all rules in the Access Control Policy and mass change them

See "desiredState" variable inside, settings are self-explanatory

You can also specify CSV-file with "SecurityZone;Subnet" columns, script will try to find and set destination zones in the rules

Script will also delete 'deny ip any any' rules by default and warn about 'permit ip any any' rules

Screen output will be logged into 'fmc_mass_log.log' text file

## Usage

fmc_mass_log <FMC_address> <Policy_Name> [<VRF-Subnet.csv> [Default-Zone-Name]]

If Default-Zone-Name is specified, script will assume that every network missing in CSV belongs to default zone.

### Example of suitable CSV content

Net_1;192.168.0.0/24

Net_2;192.168.10.128/25

Inside_DMZ;10.0.0.0/8

Net_1;192.168.30.0/24
