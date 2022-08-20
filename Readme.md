# User account synchronization

This is a suite of scripts to export user account information from a workstation
and sync it to a management server somewhere reachable via ssh.

The idea is that each workstation can be a source of new user accounts and
password changes that are mirrored to all other workstations in the cluster.

## Installation

1. Clone the git repository to /opt/trusted-computer-useraccount-sync on
   the management server and all workstations
2. Make sure you can reach the workstation machines as the root user with ssh keys
3. Make sure to have a system user named `login` on the management server and
   add the root ssh key of all workstations to the authorized keys
4. Install syncback on the workstations: `systemctl enable --now account-syncback@<machinename>.timer`
5. Install account push on the management server for each workstation you want
   to push to: `systemctl enable --now account-sync@<workstation>.timer`
