Only signed dbx-rs .dbxsecret envelopes belong here.

Never place authority private keys, client identities, database passwords, connection strings, or
local encrypted-store files in this directory. The daemon authenticates and imports envelopes into
installation-local protected storage before database workers use their local:<name> references.
