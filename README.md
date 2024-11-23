# Active Directory HIBP Auditing

Automate auditing of your Active Directory environment with Have I Been Pwned.

## Overview

Most people know that modern security recommendations don't typically recommend expiring passwords anymore.

This is true whether you follow NIST, Microsoft, or any number of other reputable sources.

Let's take a look at exactly what NIST says in SP 800-63B:

>Verifiers SHOULD NOT require memorized secrets to be changed arbitrarily (e.g., periodically). However, verifiers SHALL force a change if there is evidence of compromise of the authenticator.

In the discussion and FAQ's, NIST gives further guidance, clarifying that users tend to choose weaker memorized secrets when they know that they will have to change them in the near future. They often use a transformation such as incrementing a number, giving a false sense of security while offering no meaningful protection against cracking.

NIST instead recommends, enforcing password changes when the secret has been compromised, or if behaviour suggests fraudulent activity. 

Let's take a look at how this works in practice in an Active Directory environment.

## The landscape

Most enterprise and medium sized businesses are running an Active Directory environment. Despite its shortcomings, it's a capable directory service, if not a little difficult to harden and secure.

### Password filtering

There is some free and open source password filter solutions such as [Lithnet Password Protection](https://github.com/lithnet/ad-password-protection) which offer the ability to install directly on a Domain Controller and block compromised passwords from being used. A lot of organizations, mine included, wouldn't be comfortable with the risk of installing an external third party library directly onto a domain controller, that has direct control over user and account credentials. 

If you are Entra ID licensed and hybrid, you can deploy the [Microsft Entra Password Protection Service](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad-on-premises). I have deployed this myself, and it's straight forward and effective. It doesn't offer on-going breach monitoring, but it does prevent users from using obviously weak passwords, or those in our custom wordlist.

### Breach detection

There are a number of commercial offerings for breached password detection. I haven't actually tested any of them, so I won't comment on them. But there are many major vendors who offer a product.

For domain/account checking for future breaches, I'm a big fan of [Have I Been Pwned](https://haveibeenpwned.com/). Troy Hunt generously offers the entirety of the pwned hash list available for download, for free.

Now here's the thing, how do you compare the hashes against those in your environment? There is the excellent open source [DSInternals](https://github.com/MichaelGrafnetter/DSInternals) PowerShell tool, this is a manual process though, requiring you to run the commands every time you want to check your environment. 

You can use something like impacket to try and do it from Linux as well, but you will likely set off a *lot* of EDR alerts. Ask me how I know. It's a fun call from the SOC.

Well, let's try to see if we can implement a simple PowerShell based open-source solution that will solve the problem. 

## The free solution

The obvious answer? Roll a set of scripts you can run on a server that will securely do this work and expire user passwords if they're detected to be breached.

Well, fortunately, I've done that, and I've thought about some of the potential security pitfalls you should think about as well. You'll likely want a professional to go over what's appropriate for your environment. 

### Architecture

Best practices are now to enforce password expiry using Fine Grained Password Policies (FGPP). These are applied against users and groups, and not OUs. That's fine, but a bit annoying, you'll see why in a moment.

You can read the documentation on configuring [FGPP here.](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/fine-grained-password-policies?tabs=adac)

You should set things like minimum length, password history, and complexity requirements, according to your own organizational requirements. NIST does recommend, that if a sufficiently long password is required, such as 16 characters, complexity requirements may not be necessary as the entropy will be sufficiently secure.

If your needs are simple, setting the applied group to `Domain Users` may be sufficient. But if you're running a more complicated directory, you may have multiple groups and OU's that change frequently. We'll solve that by doing something called "Shadow Groups". This is simply "shadowing" an OU by having a script populate its membership periodically based on the membership. 

You'll want to create 2 different FGPP, one with an expiry time for passwords of something reasonably short (7-15 days), and one without an expiry time. You will want the expiry time to be *longer* than your password reminder time by at least one day. The precedence of the expiring one should be *higher* in the order than the non-expiring.

We'll automate downloading the latest HIBP list of breached NTLM hashes, which as of this writing, is over 30GB of data. Large, but not so large that it is unreasonable on a decent connection to do this nightly or weekly.

Finally, we'll have a script that checks all hashes in AD against the pwned password hash list, it will add any users with a breached password to a group that can be applied to the FGPP that has an expiry, and ensure all other user passwords are in the one without an expiry. 

### The code

I've created a [GitHub repository](https://github.com/litobro/ad-hibp-audit) that has all the relevant scripts and setup instructions, I'll go over some of them here. I don't recommend using this code without understanding clearly what each script does. As always, use at your own risk.

There are 3 PowerShell scripts provided. 

- AuditPasswords.ps1
	- Downloads the latest HIBP hash list, checks users in a target group, adds users to a breached group of users
- ShadowUsers.ps1
	- Takes an OU and group, adds all *enabled* users in OU to group
- UnshadowDisabledUsers.ps1
	- Removes all disabled users from a group

They're fairly straightforward, and my apologies, but they have a few hard coded things in them. They should be easy for any competent administrator to modify as necessary. 

Run them using the task scheduler at a reasonable time, and they should do the magic for you. 

##### Bonus

I've included a couple bonus scripts in the powershell/gMSA folder. They're undocumented, uncommented, but simple helpers to do things like change the RunAs user or add a task to the TaskScheduler. I'm a *nix person normally, so I like to keep some helpers on hand for PowerShell and Windows purposes. (insert meme about btw I run arch)

#### Dependencies

##### PowerShell Modules

- [ActiveDirectory](https://learn.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps)
- [DSInternals](https://github.com/MichaelGrafnetter/DSInternals)

##### Dotnet Tools

- [PwnedPasswordsDownloader](https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader)

The script is configured to use the `PwnedPasswordsDownloader` tool to download the latest HIBP hash list. This is a .NET tool, and you'll need to install it using the `dotnet` CLI. It's hardcoded in the script to expect the file at `C:\scripts\haveibeenpwned-downloader.exe`, but you can modify this to your environment. 


##### Permissions

You'll need to run the scripts as a user that has the following permissions:

- Read all users in the target OU
- Read all users in the breached group
- Add users to the breached group
- Remove users from the breached group

You can use a service account for this, or a domain admin, but I'd recommend using a service account.

You'll also need a user that has `Replicating Directory Changes` and `Replicating Directory Changes All` permissions on the domain. This is a *serious* privilege, and you should understand what this means and how it applies to your org. You can use a service account for this, or a domain admin, but I'd recommend using a service account.

### Security

There's going to be a few important considerations. You are creating an account with access to replicate password hashes out of your Domain Controllers, this is a *serious* privilege and risk. You need to understand what this means and how it applies to your org. 

These hashes will be stored in memory on a server, that means that if the server is compromised, an attacker may have access to your entire directory password hash list. Protect this server like it is a domain controller. Use your organizational best practices, or consult a security professional.

I recommend using group [Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/group-managed-service-accounts-overview)(gMSA) for this deployment. Jorge Bernhardt has [written an excellent guide](https://www.jorgebernhardt.com/how-to-create-a-group-managed-service-accounts-gmsa/) on how to deploy these. 

The service account will need these permissions:
- Replicating Directory Changes
- Replicating Directory Changes All

WARNING: Make sure you understand these permissions and their impacts. Configure the gMSA to only allow its credential from your monitoring server. 

I'd recommend taking additional precautions with this server, ensure it is dedicated to this task, and use microsegmentation and host based firewall and detection. Consider configuring your perimeter firewalls to only allow access to/from the device at certain times, and automatically shutting the machine down when it is not in use.

### Deployment

Create a series of scheduled tasks to deploy these scripts. Like I've said, I recommend using service accounts as the executing user. Configuring the tasks to run as a service account is an excerise for the reader but not particularly difficult, you just need to use some powershell.

#### Tasks

##### ShadowUsers / UnshadowDisabledUsers

I've scheduled my ShadowUsers.ps1 to run for each of my OUs to my related groups hourly. This is sufficient for my organization, but depending on your user count, requirements, and resources, you may want this to be higher or lower.

#### AuditPasswords

I run this nightly, I chose a time that would be fairly late, when few users are active. It doesn't really matter, but consider picking something like two or three AM as this does cause some network strain as well as impact your AD by replicating hashes out of it. 

There are flags available for if you just want to generate a test output or skip the hash download. 

## Help

If you need help, I can't promise I can solve the problem for you, but open an issue on the Github repo and I'll see what I can do. Alternatively, try emailing me as that's the best other way to get a hold of me. My personal contact information is all available on my [website](https://thomasdang.ca/contact/). 

The script will generate some logs regarding who has been added to the groups and removed automatically. You may want to create a cleanup script for these log files. 