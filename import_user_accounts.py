import sys
import json

data = json.load(sys.stdin)

#
# filter /etc/passwd
#

print('/etc/passwd')

result = []

with open('/etc/passwd', 'r') as fp:
    for line in fp:
        line = line.strip()
        
        # split into parts
        username, _, uid, gid, description, homedir, shell = line.split(":")
        
        # only include users with uid >= 1000 and username is not `nobody`
        if int(uid) < 1000 or username == 'nobody':
            result.append(f'{username}:x:{uid}:{gid}:{description}:{homedir}:{shell}')

for user in data['passwd']:
    result.append(f'{user["username"]}:x:{user["uid"]}:{user["gid"]}:{user["description"]}:{user["home"]}:{user["shell"]}')
    
with open('/etc/passwd', 'w') as fp:
    fp.writelines(result)

known_users = [v['username'] for v in data['passwd']]

#
# filter /etc/shadow
#

result = []

with open('/etc/shadow', 'r') as fp:
    for line in fp:
        line = line.strip()
        
        # split into parts
        username, password_hash, last_change, min_days, max_days, warn_days, inactive_days, expire, flag = line.split(":")
        
        # only include users with uid >= 1000 and username is not `nobody`
        if username not in known_users:
            result.append(f'{username}:{password_hash}:{last_change}:{min_days}:{max_days}:{warn_days}:{inactive_days}:{expire}:{flag}')

for user in data['shadow']:
    result.append(f'{user["username"]}:{user["password"]}:{user["last_change"]}:{user["min_days"]}:{user["max_days"]}:{user["warn_days"]}:{user["inactive"]}:{user["expire"]}:')

with open('/etc/shadow', 'w') as fp:
    fp.writelines(result)

#
# filter /etc/group
#

result = []

with open('/etc/group', 'r') as fp:
    for line in fp:
        line = line.strip()
        
        # split into parts
        groupname, _, gid, members = line.split(":")

        if members != '':
            members = members.split(',')
        else:
            members = []
        
        if groupname in data['group_memberships']:
            for m in data['group_memberships'][groupname]:
                if m not in members:
                    members.append(m)

        # only user groups, not system groups
        if int(gid) < 1000 or groupname == 'nobody':
            result.append(f'{groupname}:x:{gid}:{",".join(members)}')
 
for group in data['groups']:
    members = []
    if group['name'] in data['group_memberships']:
        members = data['group_memberships'][group['name']]
    result.append(f'{group["name"]}:x:{group["gid"]}:{",".join(members)}')
    
with open('/etc/group', 'w') as fp:
    fp.writelines(result)

known_groups = [v['name'] for v in data['groups']]

#
# filter /etc/gshadow
#

result = []

with open('/etc/gshadow', 'r') as fp:
    for line in fp:
        line = line.strip()
        
        # split into parts
        groupname, passwd, admins, members = line.split(":")

        if members != '':
            members = members.split(',')
        else:
            members = []
        
        if groupname in data['group_memberships']:
            for m in data['group_memberships'][groupname]:
                if m not in members:
                    members.append(m)

        # only user groups, not system groups
        if groupname not in known_groups:
            result.append(f'{groupname}:{passwd}:{admins}:{",".join(members)}')
 
for group in data['groups']:
    members = []
    if group['name'] in data['group_memberships']:
        members = data['group_memberships'][group['name']]
    result.append(f'{group["name"]}:!::{",".join(members)}')
    
with open('/etc/gshadow', 'w') as fp:
    fp.writelines(result)