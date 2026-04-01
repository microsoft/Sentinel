# Behavioral Attack Chain Analysis - GQL Query Examples

---

## Query 1: Explore the Graph

**Business Question:** Get a first look at the graph structure - see how behaviors connect to IPs, tactics, and alerts.

> **View:** Graph - visual node/edge traversal in Graph Explorer

```gql
MATCH (n)-[e]->(m)
RETURN n, e, m
LIMIT 15
```

---

## Query 2: Behavior to IP Topology (Graph)

**Business Question:** How are behaviors connected to IP addresses? Visualize the behavior-to-IP relationships.

> **View:** Graph - visual node/edge traversal in Graph Explorer

```gql
MATCH (b:Behavior)-[bi:BehaviorInvolvesIP]->(ip:IP)
RETURN b, bi, ip
LIMIT 10
```

---

## Query 3: Full Attack Chain - Behavior to IP to Alert with MITRE (Graph)

**Business Question:** Visualize the complete attack chain: behavior maps to tactic, involves an IP, and that IP triggered an alert. This is the full multi-hop investigation view.

> **View:** Graph - visual node/edge traversal in Graph Explorer

```gql
MATCH (b:Behavior)-[bi:BehaviorInvolvesIP]->(ip:IP)-[ita:IPTriggeredAlert]->(a:Alert),
      (b)-[bt:BehaviorMappedToTactic]->(t:Tactic)
RETURN b, bi, ip, ita, a, bt, t
LIMIT 10
```

---

## Query 4: AWS Blast Radius with Full MITRE Context (Graph)

**Business Question:** Visualize the complete cross-cloud chain: behavior involves IP and AWS resource, maps to both tactic and technique.

> **View:** Graph - visual node/edge traversal in Graph Explorer

```gql
MATCH (b:Behavior)-[bi:BehaviorInvolvesIP]->(ip:IP),
      (b)-[ba:BehaviorInvolvesAWSResource]->(r:AWSResource),
      (b)-[bt:BehaviorMappedToTactic]->(t:Tactic),
      (b)-[bte:BehaviorMappedToTechnique]->(tech:Technique)
RETURN b, bi, ip, ba, r, bt, t, bte, tech
LIMIT 10
```
## Query 5: Explore All Behaviors

**Business Question:** What behaviors were detected in my environment?

> **View:** Table

```gql
MATCH (b:Behavior)
RETURN b.Title, b.ActionType, b.ServiceSource, b.Description
LIMIT 20
```

---

## Query 6: MITRE Tactic Mapping

**Business Question:** What MITRE tactics are behaviors mapping to?

> **View:** Table

```gql
MATCH (b:Behavior)-[bt:BehaviorMappedToTactic]->(t:Tactic)
RETURN b.Title, b.ActionType, t.TacticId
LIMIT 20
```

---

## Query 7: MITRE Technique Mapping

**Business Question:** What MITRE techniques are associated with detected behaviors?

> **View:** Table

```gql
MATCH (b:Behavior)-[bte:BehaviorMappedToTechnique]->(tech:Technique)
RETURN b.Title, b.ActionType, tech.TechniqueId
LIMIT 20
```

---

## Query 8: IP-Triggered Security Alerts

**Business Question:** Which IPs triggered security alerts and what is the severity?

> **View:** Table

```gql
MATCH (ip:IP)-[ita:IPTriggeredAlert]->(a:Alert)
RETURN ip.IPAddress, a.Title, a.Severity, a.Category
LIMIT 20
```

---

## Query 9: AWS Resources Involved in Behaviors

**Business Question:** Which AWS resources are involved in detected behaviors, and what tactics apply?

> **View:** Table

```gql
MATCH (b:Behavior)-[ba:BehaviorInvolvesAWSResource]->(r:AWSResource),
      (b)-[bt:BehaviorMappedToTactic]->(t:Tactic)
RETURN b.Title, r.CloudResourceId, r.CloudPlatform, t.TacticId
LIMIT 20
```

---

## Query 10: Behavior to IP to Alert Chain

**Business Question:** Which behaviors involve IPs that also triggered alerts? This is a multi-signal correlation: behavioral detection confirmed by an independent alert.

> **View:** Table

```gql
MATCH (b:Behavior)-[bi:BehaviorInvolvesIP]->(ip:IP)-[ita:IPTriggeredAlert]->(a:Alert)
RETURN ip.IPAddress, b.Title AS Behavior, a.Title AS Alert, a.Severity
LIMIT 20
```

---

## Query 11: Behavior with Tactic + Technique + IP

**Business Question:** Which behaviors span both a MITRE tactic and technique while involving a specific IP? This reveals the full ATT&CK context for each suspicious IP.

> **View:** Table

```gql
MATCH (b:Behavior)-[bt:BehaviorMappedToTactic]->(t:Tactic),
      (b)-[bte:BehaviorMappedToTechnique]->(tech:Technique),
      (b)-[bi:BehaviorInvolvesIP]->(ip:IP)
RETURN b.Title, t.TacticId, tech.TechniqueId, ip.IPAddress
LIMIT 20
```

---

## Query 12: Alert Convergence - IPs in Both Alerts and Behaviors

**Business Question:** Which IPs appear in both behavioral detections AND security alerts with their MITRE tactic context? These are the highest-confidence threat indicators.

> **View:** Table

```gql
MATCH (b:Behavior)-[bi:BehaviorInvolvesIP]->(ip:IP)-[ita:IPTriggeredAlert]->(a:Alert),
      (b)-[bt:BehaviorMappedToTactic]->(t:Tactic)
RETURN ip.IPAddress, a.Title AS Alert, a.Severity, b.Title AS Behavior, t.TacticId AS Tactic
LIMIT 20
```

---

## Query 13: Cross-Cloud Blast Radius - IP to AWS with Tactic

**Business Question:** Which IPs are involved in behaviors that also touch AWS resources? This reveals cross-cloud attack surface with MITRE context.

> **View:** Table

```gql
MATCH (b:Behavior)-[bi:BehaviorInvolvesIP]->(ip:IP),
      (b)-[ba:BehaviorInvolvesAWSResource]->(r:AWSResource),
      (b)-[bt:BehaviorMappedToTactic]->(t:Tactic)
RETURN ip.IPAddress, b.Title, r.CloudResourceId, t.TacticId
LIMIT 20
```

---

