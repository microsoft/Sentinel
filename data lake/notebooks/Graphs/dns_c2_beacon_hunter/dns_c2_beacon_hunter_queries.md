# DNS C2 Beacon Hunter - GQL Query Examples

---

## Query 1: Explore the Graph

**Business Question:** Get a first look at the DNS topology - see how devices, domains, IPs, and threat indicators connect.

> **View:** Graph - visual node/edge traversal in Graph Explorer

```gql
MATCH (n)-[e]->(m)
RETURN n, e, m
LIMIT 15
```

---

## Query 2: Full DNS Topology (Graph)

**Business Question:** Visualize the complete DNS chain: device queries domain, domain resolves to IP.

> **View:** Graph - visual node/edge traversal in Graph Explorer

```gql
MATCH (d:Device)-[q:Queried]->(dom:Domain)-[rt:ResolvesTo]->(ip:ResolvedIP)
RETURN d, q, dom, rt, ip
LIMIT 10
```

---

## Query 3: TI-Matched Domains (Graph)

**Business Question:** Visualize which domains match threat intelligence indicators.

> **View:** Graph - visual node/edge traversal in Graph Explorer

```gql
MATCH (dom:Domain)-[mt:MatchesTI]->(ti:ThreatIndicator)
RETURN dom, mt, ti
LIMIT 10
```

---

## Query 4: Device to Domain to TI Chain (Graph)

**Business Question:** Visualize the full chain: which devices query domains that match TI indicators? This is the most critical investigation view - from endpoint to confirmed IOC.

> **View:** Graph - visual node/edge traversal in Graph Explorer

```gql
MATCH (d:Device)-[q:Queried]->(dom:Domain)-[mt:MatchesTI]->(ti:ThreatIndicator)
RETURN d, q, dom, mt, ti
LIMIT 10
```

---

## Query 5: Device Beaconing to TI Domain with Resolution (Graph)

**Business Question:** Visualize the full investigation chain: device beaconing to a TI-matched domain with its resolved IP infrastructure. This is the complete DNS C2 detection view.

> **View:** Graph - visual node/edge traversal in Graph Explorer

```gql
MATCH (d:Device)-[q:Queried]->(dom:Domain)-[mt:MatchesTI]->(ti:ThreatIndicator),
      (dom)-[rt:ResolvesTo]->(ip:ResolvedIP)
RETURN d, q, dom, mt, ti, rt, ip
LIMIT 10
```

---

## Query 6: Domain with Parent and TI Match (Graph)

**Business Question:** Visualize domains with their parent domain hierarchy and TI matches. Shows how subdomains of the same parent cluster around threat infrastructure.

> **View:** Graph - visual node/edge traversal in Graph Explorer

```gql
MATCH (dom:Domain)-[mt:MatchesTI]->(ti:ThreatIndicator),
      (dom)-[so:SubdomainOf]->(pd:ParentDomain)
RETURN dom, mt, ti, so, pd
LIMIT 10
```
## Query 7: Device DNS Queries

**Business Question:** Which devices are querying which domains and how frequently?

> **View:** Table

```gql
MATCH (d:Device)-[q:Queried]->(dom:Domain)
RETURN d.DeviceName, dom.QueryName, q.QueryCount
LIMIT 20
```

---

## Query 8: Beaconing Detection - Regular Intervals

**Business Question:** Which device-domain pairs show regular DNS query intervals? Low coefficient of variation indicates mechanical, automated beaconing.

> **View:** Table

```gql
MATCH (d:Device)-[q:Queried]->(dom:Domain)
WHERE q.MeanIntervalSec > 0
RETURN d.DeviceName, dom.QueryName, q.QueryCount, q.MeanIntervalSec, q.ActiveHoursRatio
LIMIT 20
```

---

## Query 9: Domain to IP Resolution Map

**Business Question:** Which domains resolve to which IPs and how many connections were observed?

> **View:** Table

```gql
MATCH (dom:Domain)-[rt:ResolvesTo]->(ip:ResolvedIP)
RETURN dom.QueryName, ip.RemoteIP, rt.ConnectionCount
LIMIT 20
```

---

## Query 10: Domain Parent Hierarchy

**Business Question:** How do domains cluster under parent domains? This reveals infrastructure grouping and potential DGA patterns.

> **View:** Table

```gql
MATCH (dom:Domain)-[so:SubdomainOf]->(pd:ParentDomain)
RETURN dom.QueryName, pd.ParentDomain
LIMIT 20
```

---

## Query 11: TI-Matched Domains

**Business Question:** Which domains match threat intelligence indicators? These are confirmed IOC hits.

> **View:** Table

```gql
MATCH (dom:Domain)-[mt:MatchesTI]->(ti:ThreatIndicator)
RETURN dom.QueryName, ti.ObservableValue, ti.Confidence
LIMIT 20
```

---

## Query 12: NXDOMAIN Ratio Anomalies

**Business Question:** Which device-domain pairs have high NXDOMAIN ratios? High NXDOMAIN rates suggest DGA activity or DNS tunneling attempts.

> **View:** Table

```gql
MATCH (d:Device)-[q:Queried]->(dom:Domain)
WHERE q.NxdomainRatio > 0.3
RETURN d.DeviceName, dom.QueryName, q.NxdomainRatio, q.QueryCount
LIMIT 20
```

---

## Query 13: Guilt by Association - Domains Sharing Resolved IP

**Business Question:** Which domains resolve to the same IP? If one domain is TI-flagged, other domains sharing its IP infrastructure are suspicious by association.

> **View:** Table

```gql
MATCH (dom1:Domain)-[rt1:ResolvesTo]->(ip:ResolvedIP)<-[rt2:ResolvesTo]-(dom2:Domain)
RETURN dom1.QueryName AS Domain1, dom2.QueryName AS Domain2, ip.RemoteIP AS SharedIP
LIMIT 20
```

---

