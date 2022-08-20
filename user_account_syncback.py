import os
import sys
import json

DB_FILE='user_db.json'

if os.path.exists(DB_FILE):
    with open(DB_FILE, 'r') as fp:
        database = json.load(fp)
else:
    database = {
        "passwd": [],
        "groups": [],
        "shadow": [],
        "group_memberships": {}
    }

data = json.load(sys.stdin)

#
# check for users
#

for user in data['passwd']:
    
    # add new users
    if user['username'] not in [v['username'] for v in database['passwd']]:
        
        # sanity check: uid collision?
        for v in database['passwd']:
            if v['uid'] == user['uid']:
                raise ValueError(f"Duplicate uid {v['uid']} for user {v['username']} in DB and new user {user['username']}")
        print(f'Adding new user {user["username"]}, uid={user["uid"]}, gid={user["gid"]}')
        database['passwd'].append(user)
    
#
# check for passwd change
#

for user in data['shadow']:
    # check if user is new
    if user['username'] not in [v['username'] for v in database['shadow']]:
        print(f'Adding password for user {user["username"]}')
        database['shadow'].append(user)
    
    # find user in db
    for u in database['shadow']:
        if user['username'] == u['username']:
            if user['last_change'] >= u['last_change']:
                # overwrite user
                print(f'Changing password of user {user["username"]}')
                u.update(user)

#
# check for new groups
#

for group in data['groups']:
    
    # add new users
    if group['name'] not in [v['name'] for v in database['groups']]:
        
        # sanity check: uid collision?
        for v in database['groups']:
            if v['gid'] == group['gid']:
                raise ValueError(f"Duplicate gid {v['gid']} for group {v['name']} in DB and new group {group['name']}")
        print(f'Adding new group {group["name"]}, gid={group["gid"]}')
        database['groups'].append(group)

#
# check for group membership changes
#

for group, members in data['group_memberships'].items():
    
    if group in database['group_memberships']:
        if database['group_memberships'][group] != members and len(database['group_memberships'][group]) < len(members):
            print(f'Changing group memberships for {group} from {",".join(database["group_memberships"][group])} to {",".join(members)}')
            database['group_memberships'][group] = members
    else:
            print(f'Adding group memberships for {",".join(members)} to {group}')
            database['group_memberships'][group] = members
        

# save database again
with open(DB_FILE, 'w') as fp:
    json.dump(database, fp, indent=4)