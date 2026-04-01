# Phishing Email-to-Endpoint Kill Chain - GQL Query Examples

> **Tier Zero Queries:** Queries 1-5 return graph visualizations for immediate investigation. Queries 6-15 return tabular results for detailed analysis.

---

## Query 1: Explore the Graph

**Business Question:** Get a first look at the phishing kill chain - see how senders, emails, users, URLs, attachments, and devices connect.

> **View:** Graph - visual node/edge traversal in Graph Explorer

```gql
MATCH (n)-[e]->(m)
RETURN n, e, m
LIMIT 15
```

---

## Query 2: Sender to Email to Recipient Chain (Graph)

**Business Question:** Visualize the email delivery chain: who sent what to whom, and where was it delivered?

> **View:** Graph - visual node/edge traversal in Graph Explorer

```gql
MATCH (s:Sender)-[se:Sent]->(e:Email)-[re:ReceivedEmail]->(u:User)
RETURN s, se, e, re, u
LIMIT 10
```

---

## Query 3: Email to URL to Click Chain (Graph)

**Business Question:** Visualize which emails contain URLs and which users clicked them. This is the click-through exposure view.

> **View:** Graph - visual node/edge traversal in Graph Explorer

```gql
MATCH (e:Email)-[cu:ContainsUrl]->(url:Url)<-[cl:ClickedUrl]-(u:User)
RETURN e, cu, url, cl, u
LIMIT 10
```

---

## Query 4: Full Kill Chain: Email to Attachment to Process to Device (Graph)

**Business Question:** Visualize the complete kill chain: email carries attachment, attachment triggers process execution on endpoint device. This multi-hop traversal is impossible in flat KQL.

> **View:** Graph - visual node/edge traversal in Graph Explorer

```gql
MATCH (e:Email)-[ha:HasAttachment]->(att:Attachment)-[tp:TriggeredProcess]->(p:Process)-[od:OnDevice]->(d:Device)
RETURN e, ha, att, tp, p, od, d
LIMIT 10
```

---

## Query 5: Full Campaign Topology (Graph)

**Business Question:** Visualize the complete campaign structure: sender to emails to recipients, with URL links. Shows the full blast radius in one view.

> **View:** Graph - visual node/edge traversal in Graph Explorer

```gql
MATCH (s:Sender)-[se:Sent]->(e:Email)-[re:ReceivedEmail]->(u:User),
      (e)-[cu:ContainsUrl]->(url:Url)
RETURN s, se, e, re, u, cu, url
LIMIT 10
```

---

## Query 6: Email Recipients and Delivery Location

**Business Question:** Who received phishing emails and where were they delivered (Inbox, Quarantine, Junk)?

> **View:** Table

```gql
MATCH (e:Email)-[re:ReceivedEmail]->(u:User)
RETURN e.Subject, u.UserEmail, re.DeliveryAction, re.DeliveryLocation
LIMIT 20
```

---

## Query 7: Sender Volume Analysis

**Business Question:** Which senders sent the most emails? High-volume senders may indicate campaign infrastructure.

> **View:** Table

```gql
MATCH (s:Sender)-[se:Sent]->(e:Email)
RETURN s.SenderEmail, COUNT(*) AS EmailCount
LIMIT 20
```

---

## Query 8: Email Attachments with Threat Detection

**Business Question:** Which email attachments have detected threats? Shows file type, size, and threat classification.

> **View:** Table

```gql
MATCH (e:Email)-[ha:HasAttachment]->(att:Attachment)
RETURN e.Subject, att.FileName, att.FileType, att.ThreatTypes, att.ThreatNames
LIMIT 20
```

---

## Query 9: URL Click Analysis

**Business Question:** Which users clicked on URLs from phishing emails? Did they click through the Safe Links warning?

> **View:** Table

```gql
MATCH (u:User)-[cl:ClickedUrl]->(url:Url)
RETURN u.UserEmail, url.UrlDomain, cl.IsClickedThrough, cl.ActionType
LIMIT 20
```

---

## Query 10: Attachment to Process Execution

**Business Question:** Which attachments triggered process execution on endpoint devices? This traces the payload detonation chain.

> **View:** Table

```gql
MATCH (att:Attachment)-[tp:TriggeredProcess]->(p:Process)-[od:OnDevice]->(d:Device)
RETURN att.FileName, p.FileName, p.ProcessCommandLine, d.DeviceName
LIMIT 20
```

---

## Query 11: User Downloaded Files

**Business Question:** Which users downloaded files (attachments) on their endpoints? Includes the download source URL.

> **View:** Table

```gql
MATCH (u:User)-[df:DownloadedFile]->(att:Attachment)
RETURN u.UserEmail, att.FileName, df.DeviceName, df.FileOriginUrl
LIMIT 20
```

---

## Query 12: Campaign Infrastructure - URLs Shared Across Emails

**Business Question:** Which URLs appear in multiple different phishing emails? Shared URLs indicate coordinated campaign infrastructure reuse.

> **View:** Table

```gql
MATCH (e1:Email)-[cu1:ContainsUrl]->(url:Url)<-[cu2:ContainsUrl]-(e2:Email)
RETURN e1.Subject AS Email1, e2.Subject AS Email2, url.UrlDomain AS SharedDomain
LIMIT 20
```

---

## Query 13: Reused Payloads - Attachment in Multiple Emails

**Business Question:** Which attachments (by SHA256 hash) appear in multiple phishing emails? Reused payloads indicate the same malware distributed across campaign waves.

> **View:** Table

```gql
MATCH (e1:Email)-[ha1:HasAttachment]->(att:Attachment)<-[ha2:HasAttachment]-(e2:Email)
RETURN att.FileName, e1.Subject AS Email1, e2.Subject AS Email2
LIMIT 20
```

---

## Query 14: Email with Both Attachment AND URL

**Business Question:** Which emails carry both attachments and embedded URLs? Dual-vector emails (URL + attachment) are higher risk as they provide two attack paths.

> **View:** Table

```gql
MATCH (e:Email)-[ha:HasAttachment]->(att:Attachment),
      (e)-[cu:ContainsUrl]->(url:Url)
RETURN e.Subject, att.FileName, url.UrlDomain
LIMIT 20
```

---

## Query 15: Sender to Email to User to Click (4-hop Graph)

**Business Question:** Visualize the full 4-hop chain: sender sent email, email delivered to user, user clicked URL. This is the click-exposure investigation view.

> **View:** Graph - visual node/edge traversal in Graph Explorer

```gql
MATCH (s:Sender)-[se:Sent]->(e:Email)-[re:ReceivedEmail]->(u:User)-[cl:ClickedUrl]->(url:Url)
RETURN s, se, e, re, u, cl, url
LIMIT 10
```

---

## Query 16: Attachment StoredOn Device (Graph)

**Business Question:** Which attachments were extracted by Outlook and saved on endpoint devices?

> **View:** Graph - visual node/edge traversal in Graph Explorer

```gql
MATCH (att:Attachment)-[so:StoredOn]->(d:Device)
RETURN att, so, d
LIMIT 10
```

---

## Query 17: Email Domains Matching Threat Intelligence

**Business Question:** Which email domains match threat intelligence indicators? This connects phishing infrastructure to known-bad domains.

> **View:** Table

```gql
MATCH (e:Email)-[hd:HasDomain]->(dom:Domain)<-[dr:DomainRelatedTo]-(ti:ThreatIndicator_Domain)
RETURN e.Subject, dom.DomainId, ti.TIDomain, ti.Confidence
LIMIT 20
```

---

## Query 18: TI Domain Matches (Graph)

**Business Question:** Visualize which domains in the phishing campaign match threat intelligence indicators.

> **View:** Graph - visual node/edge traversal in Graph Explorer

```gql
MATCH (ti:ThreatIndicator_Domain)-[dr:DomainRelatedTo]->(dom:Domain)
RETURN ti, dr, dom
LIMIT 10
```

---

## Query 19: TI URL Matches (Graph)

**Business Question:** Visualize which URLs in the phishing campaign match threat intelligence indicators.

> **View:** Graph - visual node/edge traversal in Graph Explorer

```gql
MATCH (ti:ThreatIndicator_Url)-[ur:UrlRelatedTo]->(url:Url)
RETURN ti, ur, url
LIMIT 10
```
