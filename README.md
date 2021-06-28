# FMC_Mass_Log

Script to find all rules in the Access Control Policy and mass change them

See _desiredState_ variable inside, settings are self-explanatory

You can also specify CSV-file with `"SecurityZone;Subnet"` columns, script will try to find and set destination zones in the rules

If _[Default-Zone-Name]_ is specified, script will assume that every network missing in CSV-file belongs to that zone.

Also, it will check all the rules where _[Default-Zone-Name]_ is the only SrcZone and try to find and set source zone(s).

Script will  delete _'deny ip any any'_ rules by default (variable _deleteDenyIPAnyAny_)

Script will warn about _'permit ip any any'_ rules, but will not delete them

Script will change all _'ALLOW'_ rules to _'TRUST'_ (variable _changeAllowToTrust_)

Screen output will be logged into _'fmc_mass_log.log'_ text file

## Usage

fmc_mass_log <FMC_address> <Policy_Name> [<VRF-Subnet.csv> [Default-Zone-Name]]


### Example of suitable CSV content

Net_1;192.168.0.0/24

Net_2;192.168.10.128/25

Inside_DMZ;10.0.0.0/8

Net_1;192.168.30.0/24
