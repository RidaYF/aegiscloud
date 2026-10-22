# AegisCloud knowledge base

Short playbooks and references used by the AI SOC analyst. Each section starts with "## ".
The "Techniques:" line lists the MITRE ATT&CK techniques the section is about.
This is lab guidance written for the project; adapt it to a real organisation's procedures.

## Playbook: stolen or abused cloud credentials
Techniques: T1078.004
Signs: a valid cloud identity is used by someone who should not have its keys, often from an unusual source. A typical first move is an identity check such as sts:GetCallerIdentity, where the attacker confirms what the stolen credentials can do.
Response, in this order:
1. disable_access_key for the affected identity. This stops the attacker immediately and can be reversed.
2. collect_more_evidence: review everything the identity did in the last 24 hours.
3. notify_team.
4. After approval, rotate the secrets and review the identity's permissions.
Blocking the source IP alone is weak against stolen keys, because the attacker can change IP and the keys still work.

## Playbook: cloud account and infrastructure discovery
Techniques: T1087.004, T1580, T1619, T1069.003
Signs: a burst of List and Describe calls (users, groups, networks, buckets) from one identity in a short time. The attacker is mapping the environment.
Severity: a discovery burst alone is medium. It becomes high or critical if it is followed by data access or by account changes from the same source.
Response: collect_more_evidence on what the identity did next, notify_team. If the source is unusual for this identity, also propose disable_access_key.

## Playbook: data read from cloud storage
Techniques: T1530
Signs: s3:GetObject on a sensitive bucket by an identity that has just performed discovery. A read is not proof of exfiltration; say so unless the evidence shows data leaving the environment.
Severity: high.
Response: collect_more_evidence to find which objects were read, disable_access_key, apply_deny_policy to block the identity from the bucket, notify_team (possible data exposure; the team decides on any reporting duties).

## Playbook: reconnaissance followed by data collection
Techniques: T1078.004, T1087.004, T1580, T1619, T1530
Pattern: discovery calls and then a read of sensitive data from the same source within minutes means a compromised identity is actively being used to find and take data.
Severity: critical. Do not rate it lower than the incident's stored severity without a stated reason.
Response priority:
1. disable_access_key for the identity.
2. apply_deny_policy so the identity cannot read the sensitive bucket.
3. notify_team.
4. collect_more_evidence about every call the identity made.
The identity is the one named in the evidence, not the source IP.

## Playbook: privilege escalation and persistence through a new cloud account
Techniques: T1136.003, T1098.003, T1098.001
Pattern: an identity creates a new user (iam:CreateUser), attaches a policy to it (iam:AttachUserPolicy) and creates an access key for it (iam:CreateAccessKey). The attacker is building a second way in that keeps working even if the original key is revoked. An identity that normally only reads data should not make IAM changes.
Severity: critical. Administrator rights on a new account give the attacker lasting control.
Two identities matter: the identity that made the changes (named as the user in the evidence) and the new identity that was created (named as the resource of the IAM calls).
Response priority:
1. disable_access_key for the identity that made the changes, because it is the compromised one.
2. disable_access_key for the newly created user, so its new key stops working.
3. apply_deny_policy for the newly created user, so the permissions it was given have no effect.
4. notify_team.
5. collect_more_evidence: list every user, policy and key created or changed by the identity.

## Reference: cloud API calls and MITRE ATT&CK techniques
Techniques: T1078.004, T1087.004, T1580, T1619, T1530, T1069.003, T1136.003, T1098.003, T1098.001
General mapping of API calls to techniques. Always check it against the evidence.
- sts:GetCallerIdentity: T1078.004, valid cloud account in use; the attacker checks which identity the credentials belong to.
- iam:ListUsers: T1087.004, cloud account discovery.
- iam:ListGroups: T1069.003, cloud groups discovery.
- ec2:DescribeVpcs: T1580, cloud infrastructure discovery.
- s3:ListAllMyBuckets and s3:ListBucket: T1619, cloud storage object discovery.
- s3:GetObject: T1530, data from cloud storage.
- iam:CreateUser: T1136.003, create cloud account, used for persistence.
- iam:AttachUserPolicy: T1098.003, additional cloud roles, gives an account more privileges.
- iam:CreateAccessKey: T1098.001, additional cloud credentials, a new key for an account.

## Reference: allowed response actions
Every action is only a proposal. A human approves it before anything runs.
- disable_access_key: target is the identity (user) whose access keys should be disabled.
- apply_deny_policy: target is the identity that should be denied access to a resource.
- block_source_ip: target is an IP address. Useful only for real external attacker addresses, and weak against stolen keys.
- notify_team: target is the security team.
- collect_more_evidence: target is the identity or resource to investigate, and the reason says what to look for.

## Guidance: severity and confidence
Use the incident's stored severity as the baseline. A single discovery burst is medium, a sensitive data read is high, discovery followed by data collection from one source is critical, and creating a new user with attached policy and access key is critical.
Confidence is high only when the evidence directly shows the behaviour. Whether the credentials were really stolen is usually not known, so say what is unknown in the uncertainties.

## Guidance: writing the analysis
Be factual and short. Cite the API calls and resources from the evidence. Do not invent users, addresses or times. If the data does not say something, put it in the uncertainties.