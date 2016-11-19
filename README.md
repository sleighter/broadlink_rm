## Broadlink RM
A library for interacting with the Broadlink RM 1, 2, and 3 IR Blaster devices.

### Usage
```
require 'broadlink_rm'

# Discover and authorize with a device
device = BroadlinkRM::Device.discover
device.auth

# Learn a code from an IR remote
device.enter_learning
# RM unit is waiting for an IR signal to learn
# After sending an ir signal to the unit
learned_code = device.check_data

# Blast a code from the device
device.send_data(learned_code)
```

### Credits
Largely ported from https://github.com/mjg59/python-broadlink
