import json

export = {}

#
# filter /etc/passwd
#

export['passwd'] = []

with open('/etc/passwd', 'r') as fp:
    for line in fp:
        line = line.strip()
        
        # split into parts
        username, _, uid, gid, description, homedir, shell = line.split(":")
        
        # only include users with uid >= 1000 and username is not `nobody`
        if int(uid) >= 1000 and username != 'nobody':
            export['passwd'].append({
                "username": username,
                "uid": int(uid),
                "gid": int(gid),
                "description": description,
                "home": homedir,
                "shell": shell
            })

known_users = [v['username'] for v in export['passwd']]

#
# filter /etc/shadow
#

export['shadow'] = []

with open('/etc/shadow', 'r') as fp:
    for line in fp:
        line = line.strip()
        
        # split into parts
        username, password_hash, last_change, min_days, max_days, warn_days, inactive_days, expire, _ = line.split(":")
        
        # only include users that have passwords set and username is not `nobody`
        if password_hash != '!*' and username != 'nobody' and username in known_users:
            export['shadow'].append({
                "username": username,
                "password": password_hash,
                "last_change": int(last_change) if last_change != '' else '',
                "min_days": int(min_days) if min_days != '' else '',
                "max_days": int(max_days) if max_days != '' else '',
                "warn_days": int(warn_days) if warn_days != '' else '',
                "inactive": int(inactive_days) if inactive_days != '' else '',
                "expire": int(expire) if expire != '' else ''
            })

#
# filter /etc/group
#

export['groups'] = []
export['group_memberships'] = {}

with open('/etc/group', 'r') as fp:
    for line in fp:
        line = line.strip()
        
        # split into parts
        groupname, _, gid, members = line.split(":")

        if members != '':
            members = members.split(',')
        else:
            members = []

        # only user groups, not system groups
        if int(gid) >= 1000 and groupname != 'nobody':
            export['groups'].append({
                "name": groupname,
                "gid": int(gid)
            })

        # if we have members set check if we have those users and add entries
        for member in members:
            if member in known_users:
                if groupname not in export['group_memberships']:
                    export['group_memberships'][groupname] = []
                export['group_memberships'][groupname].append(member)
        
print(json.dumps(export, indent=4))