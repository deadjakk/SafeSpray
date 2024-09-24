# SafeSpray
A simple smb login password spraying tool written in go that aims to prevent account lockouts.  
The difference between this tool and others is that it will only perform
password spraying on accounts that meet the following criteria:  
1. has a badpwdcount equal to 0  
2. has a username that is present in the provided userlist flag  
3. does not end in $ (computer accounts usually though this should not ever be hit since it only queries user objects)  
4. is not an account in ignoreArray (see isIgnorable function)  

Also, to get this information it will query all ldap users at the time the password
spray is performed, therefore a valid user account is needed (in most environments).

Obviously this will not be applicable to all types of engagements, but it should work
great on internal (non-stealth) pentesting engagements. 

This way you really _shouldn't_ need to worry about the password policy as long as
it allows more than 1 failed login attempt.

All this said, test it on your own first, I am not responsible for account lockouts.

# To install  
```
go install github.com/deadjakk/safespray@latest
```

# To Use
```
jakk@tele ~/spaf $ ./safespray -domain sprawl.local.shell.rip -password Password1 -spraypassword Password1 -userlist users.txt -username administrator -verbose
SKIPPED account (reason: not present in user list): Administrator
ADDED account: carnivore
loaded 1 users
SUCCESS - carnivore@sprawl.local.shell.rip with password Password1
```

# Example usage  
Note: These were both run in quick succession, and because the test account failed to authenticate on the first run, it was omitted from the second run due to the updated `badPwdCount`.  
![image](https://github.com/user-attachments/assets/31781280-0360-4a1e-87b4-a3ad0bee63ae)

