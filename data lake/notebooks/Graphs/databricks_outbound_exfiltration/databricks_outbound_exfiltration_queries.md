# Data Exfiltration Detection - Databricks Outbound Activity - GQL Query Examples

---

## Query 1: Explore the Graph

**Business Question:** Get a first look at the activity graph - see how users connect to notebooks, exports, staging files, and cloud uploads.

> **View:** Graph - visual node/edge traversal in Graph Explorer

```gql
MATCH (n)-[e]->(m)
RETURN n, e, m
LIMIT 15
```

---

## Query 2: User Export + Notebook Chain (Graph)

**Business Question:** Visualize the relationship between users, their export actions, and the notebooks they executed.

> **View:** Graph - visual node/edge traversal in Graph Explorer

```gql
MATCH (u:User)-[pe:PerformedExport]->(ea:ExportAction),
      (u)-[en:ExecutedNotebook]->(nb:Notebook)
RETURN u, pe, ea, en, nb
LIMIT 10
```

---

## Query 3: Full Exfiltration Chain (Graph)

**Business Question:** Visualize the complete exfiltration lifecycle: user exports from Databricks, stages in DBFS, uploads to cloud storage. This is the multi-hop chain that is invisible when each platform's logs are examined in isolation.

> **View:** Graph - visual node/edge traversal in Graph Explorer

```gql
MATCH (u:User)-[pe:PerformedExport]->(ea:ExportAction),
      (u)-[sf:StagedFile]->(f:DBFSFile),
      (u)-[uc:UploadedToCloud]->(cu:CloudUpload)
RETURN u, pe, ea, sf, f, uc, cu
LIMIT 10
```

---

## Query 4: User Full Topology (Graph)

**Business Question:** Visualize a user's complete activity footprint: notebooks executed and exports performed.

> **View:** Graph - visual node/edge traversal in Graph Explorer

```gql
MATCH (u:User)-[en:ExecutedNotebook]->(nb:Notebook)
MATCH (u)-[pe:PerformedExport]->(ea:ExportAction)
RETURN u, en, nb, pe, ea
LIMIT 10
```
## Query 5: User Notebook Execution

**Business Question:** Which users executed which notebooks and what is the notebook sensitivity?

> **View:** Table

```gql
MATCH (u:User)-[en:ExecutedNotebook]->(nb:Notebook)
RETURN u.UserEmail, nb.NotebookPath, nb.Sensitivity
LIMIT 20
```

---

## Query 6: User Export Actions

**Business Question:** Which users performed notebook downloads or workspace exports? After-hours exports of sensitive paths are the strongest exfiltration indicator.

> **View:** Table

```gql
MATCH (u:User)-[pe:PerformedExport]->(ea:ExportAction)
RETURN u.UserEmail, ea.ActionName, ea.ResourcePath, ea.PathSensitivity
LIMIT 20
```

---

## Query 7: User DBFS Staging Activity

**Business Question:** Which users wrote files to DBFS staging directories? This is the staging phase of the export-stage-exfiltrate pattern.

> **View:** Table

```gql
MATCH (u:User)-[sf:StagedFile]->(f:DBFSFile)
RETURN u.UserEmail, f.PathSensitivity, f.Operation
LIMIT 20
```

---

## Query 8: User Cloud Uploads

**Business Question:** Which users uploaded files to cloud storage services (OneDrive, SharePoint, etc.)?

> **View:** Table

```gql
MATCH (u:User)-[uc:UploadedToCloud]->(cu:CloudUpload)
RETURN u.UserEmail, cu.FileName, cu.TargetService
LIMIT 20
```

---

## Query 9: Sensitive Path Exports

**Business Question:** Which users exported from sensitive paths (pii, finance, production)? Sensitive path exports are the highest-priority exfiltration indicator.

> **View:** Table

```gql
MATCH (u:User)-[pe:PerformedExport]->(ea:ExportAction)
WHERE ea.PathSensitivity = 'HIGH'
RETURN u.UserEmail, ea.ActionName, ea.ResourcePath, ea.PathSensitivity
LIMIT 20
```

---

## Query 10: User Activity Overview

**Business Question:** What is each user's risk profile based on identity context and investigation priority?

> **View:** Table

```gql
MATCH (u:User)-[en:ExecutedNotebook]->(nb:Notebook)
RETURN u.UserEmail, u.Department, u.EntraRiskLevel, u.MaxInvestigationPriority
LIMIT 20
```

---

## Query 11: Export + Upload Chain

**Business Question:** Which users both exported from Databricks AND uploaded to cloud storage? This is the full exfiltration chain: export from source platform, deliver to external storage.

> **View:** Table

```gql
MATCH (u:User)-[pe:PerformedExport]->(ea:ExportAction),
      (u)-[uc:UploadedToCloud]->(cu:CloudUpload)
RETURN u.UserEmail, ea.ActionName, ea.ResourcePath, cu.FileName, cu.TargetService
LIMIT 20
```

---

## Query 12: DBFS Staging + Cloud Upload Chain

**Business Question:** Which users staged files in DBFS AND uploaded to cloud? This reveals the complete staging-to-delivery pipeline.

> **View:** Table

```gql
MATCH (u:User)-[sf:StagedFile]->(f:DBFSFile),
      (u)-[uc:UploadedToCloud]->(cu:CloudUpload)
RETURN u.UserEmail, f.PathSensitivity, cu.FileName, cu.TargetService
LIMIT 20
```

---

