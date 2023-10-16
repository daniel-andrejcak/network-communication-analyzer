"""protocols.py sluzi na nacitanie protokolov z externeho suboru
je to v osobitnom subore, aby sa zabranilo import loopingu
a aby sa to nenachadzalo v subore frame.py, kvoli prehliadnosti"""

from ruamel.yaml import YAML

yaml = YAML()

PROTOCOLSFILE = "./Protocols/protocols.yaml"

protocolsFile = open(PROTOCOLSFILE, "r")

protocols = dict(yaml.load(protocolsFile))

protocolsFile.close()