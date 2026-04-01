# OAuth & Service Principal Privilege Escalation - GQL Query Examples

> **Tier Zero Roles:** Throughout these queries, "Tier Zero" refers to the most privileged directory roles in Microsoft Entra ID (Global Administrator, Privileged Role Administrator, Privileged Authentication Administrator, Application Administrator, Cloud Application Administrator, Partner Tier2 Support, Security Administrator). An identity holding any Tier Zero role has full or near-full control over the tenant. Compromise of a Tier Zero role is equivalent to full tenant compromise. The graph flags these roles with `IsTierZero = true` on DirectoryRole nodes.

---

## Query 1: Explore the Graph

**Business Question:** Get a first look at the privilege topology - see how service principals connect to roles, permissions, and API endpoints.

> **View:** Graph - visual node/edge traversal in Graph Explorer

```gql
MATCH (n)-[e]->(m)
RETURN n, e, m
LIMIT 15
```

---

## Query 2: Consent Chain Visual (Graph)

**Business Question:** Visualize the full consent topology: service principals connected to permissions connected to consenting users. The star pattern reveals consent hubs.

> **View:** Graph - visual node/edge traversal in Graph Explorer

```gql
MATCH (sp:ServicePrincipal)-[hp:HasPermission]->(perm:AppPermission)<-[gb:GrantedBy]-(u:User)
RETURN sp, hp, perm, gb, u
LIMIT 30
```

---

## Query 3: Risky SP with Risk Events (Graph)

**Business Question:** Visualize confirmed-compromised service principals with their risk events and authentication sources.

> **View:** Graph - visual node/edge traversal in Graph Explorer

```gql
MATCH (sp:ServicePrincipal)-[h:HasRiskEvent]->(re:RiskEvent),
      (sp)-[a:AuthenticatedAs]->(ip:SourceIP)
RETURN sp, h, re, a, ip
LIMIT 20
```

---

## Query 4: Directory Role Assignments

**Business Question:** Which entities hold directory roles and which are Tier Zero?

> **View:** Table

```gql
MATCH (sp)-[hdr:HasDirectoryRole]->(dr:DirectoryRole)
RETURN hdr.MemberId, dr.RoleName, dr.IsTierZero, hdr.AssignmentType
LIMIT 20
```

---

## Query 5: Tier Zero Role Holders

**Business Question:** Which entities hold the most privileged (Tier Zero) directory roles? Compromise of any of these is equivalent to full tenant takeover.

> **View:** Table

```gql
MATCH (sp)-[hdr:HasDirectoryRole]->(dr:DirectoryRole)
WHERE dr.IsTierZero = 'true'
RETURN hdr.MemberId, dr.RoleName, hdr.AssignmentType
LIMIT 20
```

---

## Query 6: Sensitive API Callers

**Business Question:** Which service principals call sensitive API endpoints (roleManagement, addPassword, oauth2PermissionGrants, etc.)?

> **View:** Table

```gql
MATCH (sp)-[csa:CalledSensitiveAPI]->(r:Resource)
RETURN csa.SpId, r.Endpoint, csa.SensitiveCallCount, csa.PrimaryMethod
LIMIT 20
```

---

## Query 7: Authentication Sources

**Business Question:** Where are service principals authenticating from? Unusual IPs or credential types indicate compromise.

> **View:** Table

```gql
MATCH (sp)-[auth:AuthenticatedAs]->(src:SourceIP)
RETURN auth.SpId, src.IPAddress, auth.SignInCount, auth.CredentialType, auth.ResourceDisplayName
LIMIT 20
```

---

## Query 8: API Call Activity

**Business Question:** Which service principals call Graph API endpoints and how frequently?

> **View:** Table

```gql
MATCH (sp)-[ca:CalledAPI]->(r:Resource)
RETURN ca.SpId, r.Endpoint, ca.TotalCallCount, ca.PrimaryMethod
LIMIT 20
```

---

## Query 9: Consent Chain - SP to Permission to User

**Business Question:** Which users granted consent to which permissions for which service principals? This maps the trust topology.

> **View:** Table

```gql
MATCH (sp:ServicePrincipal)-[hp:HasPermission]->(perm:AppPermission)<-[gb:GrantedBy]-(u:User)
RETURN u.UserPrincipalName, perm.PermissionName, hp.GrantType
LIMIT 20
```

---

## Query 10: Transitive Consent Escalation - 4-Hop Diamond

**Business Question:** If one SP is compromised, which other SPs can be transitively reached through shared consenting users? This 4-hop diamond reveals trust chains invisible in flat logs.

> **View:** Table

```gql
MATCH (sp1:ServicePrincipal)-[hp1:HasPermission]->(p1:AppPermission)-[gb1:GrantedBy]->(u:User),
      (u)<-[gb2:GrantedBy]-(p2:AppPermission)<-[hp2:HasPermission]-(sp2:ServicePrincipal)
RETURN p1.PermissionName AS SourcePerm, u.UserPrincipalName AS SharedConsenter, p2.PermissionName AS ReachablePerm
LIMIT 20
```

---

## Query 11: Consent-to-Credential Backdoor

**Business Question:** Which users both consented permissions AND added secrets to service principals? This is the classic OAuth persistence pattern: consent phishing followed by credential implant.

> **View:** Table

```gql
MATCH (sp:ServicePrincipal)-[hp:HasPermission]->(perm:AppPermission)<-[gb:GrantedBy]-(u:User),
      (u)-[s:AddedSecretTo]->(target)
RETURN u.UserPrincipalName AS User, perm.PermissionName AS Permission
LIMIT 20
```

---

## Query 12: Triple Fork - Full SP Blast Radius

**Business Question:** What is the complete attack surface for a single SP: where it authenticates from, what regular APIs it calls, AND what sensitive APIs it touches?

> **View:** Table

```gql
MATCH (sp:ServicePrincipal)-[a:AuthenticatedAs]->(ip:SourceIP),
      (sp)-[c1:CalledAPI]->(r1:Resource),
      (sp)-[c2:CalledSensitiveAPI]->(r2:Resource)
RETURN a.SpId AS SP, ip.IPAddress AS SourceIP, r1.Endpoint AS RegularAPI, c1.TotalCallCount AS RegCalls, r2.Endpoint AS SensitiveAPI, c2.SensitiveCallCount AS SensCalls
LIMIT 20
```

---

## Query 13: Shared IP Infrastructure - Lateral Movement

**Business Question:** Which different service principals authenticate from the same IP? Same IP + different identities indicates either shared infrastructure or lateral movement.

> **View:** Table

```gql
MATCH (sp1:ServicePrincipal)-[a1:AuthenticatedAs]->(ip:SourceIP)<-[a2:AuthenticatedAs]-(sp2:ServicePrincipal)
RETURN ip.IPAddress AS SharedIP, a1.SpId AS SP1, a2.SpId AS SP2, a1.SignInCount AS SP1_SignIns, a2.SignInCount AS SP2_SignIns
LIMIT 20
```

---

## Query 14: Consent-to-API Exploitation

**Business Question:** Which consented permissions are actively being used against APIs? This bridges the consent graph with the API activity graph.

> **View:** Table

```gql
MATCH (sp:ServicePrincipal)-[hp:HasPermission]->(perm:AppPermission)<-[gb:GrantedBy]-(u:User),
      (sp)-[c:CalledAPI]->(r:Resource)
RETURN u.UserPrincipalName, perm.PermissionName, r.Endpoint, c.TotalCallCount
ORDER BY c.TotalCallCount DESC
LIMIT 20
```

---

## Query 15: Risky SP Variable-Length Reachability

**Business Question:** Starting from high-risk SPs, what can they reach within 2 hops? This maps the blast radius of a confirmed compromise using variable-length path traversal.

> **View:** Table

```gql
MATCH ACYCLIC (sp:ServicePrincipal)-[]->{1,2}(target)
WHERE sp.SpRiskLevel = 'high'
RETURN sp.SpRiskState, target.IPAddress, target.RiskEventType
LIMIT 20
```
