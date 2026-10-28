#!/bin/sh
# Supply your cloud's actual image, flavor and external networks.
python3 neutron-flux.py plan --image debian-13 --flavor x1.nano --storage host --external-networks Public1 --zones all
python3 neutron-flux.py run --image debian-13 --flavor x1.nano --storage host --external-networks Public1 --live-attempts 5 --repeat 1
python3 neutron-flux.py cleanup --dry-run
