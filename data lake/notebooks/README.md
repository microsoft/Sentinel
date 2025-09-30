# 📓 Security Analytics Notebooks for Microsoft Sentinel data lake

This repository contains a collection of **modular Jupyter/Spark notebooks** designed for use with Microsoft Sentinel data lake.  
Each folder focuses on a specific detection or analysis scenario, with supporting code, documentation, and architectural diagrams.

---

## 🚀 Getting Started

### Prerequisites

Complete the Microsoft Sentinel data lake onboarding process before using these notebooks.
[Microsoft Sentinel data lake onboarding prerequisites](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-lake-onboarding#prerequisites)

1. **Confirm Sentinel data lake enablement** - To use notebooks in the Microsoft Sentinel data lake, you must first onboard to the Sentinel data lake. If you haven't onboarded to the Microsoft Sentinel data lake, see [Onboarding to Microsoft Sentinel data lake](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-lake-onboarding).

2. **Validate data availability** - Ensure target tables (e.g., `SigninLogs` or other tables) are accessible in your sentinel workspace or Unified Security Operations with Microsoft Defender portal.

3. **Install Microsoft Sentinel extension for Visual Studio Code (VS Code)** - The Microsoft Sentinel extension for Visual Studio Code (VS Code) can be installed from the extensions marketplace. For more detailed steps, refer [Install Visual Studio Code and the Microsoft Sentinel extension](https://learn.microsoft.com/en-us/azure/sentinel/datalake/notebooks#install-visual-studio-code-and-the-microsoft-sentinel-extension)

### Additional Setup for Diagram Rendering

To view **Mermaid diagrams** embedded in these notebooks and documentation:

#### VS Code Extensions (Recommended)

Install one of these VS Code extensions for Mermaid diagram rendering:

- **[Mermaid Preview](https://marketplace.visualstudio.com/items?itemName=vstirbu.vscode-mermaid-preview)** - Dedicated Mermaid preview pane
- **[Markdown Preview Mermaid Support](https://marketplace.visualstudio.com/items?itemName=bierner.markdown-mermaid)** - Renders Mermaid in markdown preview
- **[Markdown All in One](https://marketplace.visualstudio.com/items?itemName=yzhang.markdown-all-in-one)** - Full markdown support including Mermaid

#### Alternative Options

- **GitHub**: All diagrams render natively when viewing files on GitHub
- **Markdown Preview Enhanced**: For advanced markdown features and diagram support

💡 **Note**: Without these extensions, Mermaid code blocks will display as plain text in VS Code. The diagrams are essential for understanding the notebook workflow and data pipeline architecture.

### Running in VS Code

You can run these notebooks directly from VS Code using the **Microsoft Sentinel extension for Visual Studio Code (VS Code)**.

📚 Reference: [Use notebooks in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/datalake/notebooks)

Steps:

1. Clone this repository.
2. Open the desired notebook (`.ipynb`) in VS Code.
3. Select the Microsoft Sentinel shield icon in the left toolbar and Select your account name to complete the sign in.
4. Select the Run button to execute the code in the notebook.
5. You will be prompted to select the kernel, choose Microsoft Sentinel.
6. On the next prompt, you will be prompted to choose small/medium/large sized runtime pool. For more information on the different runtimes, see [Selecting the appropriate Microsoft Sentinel runtime](https://learn.microsoft.com/en-us/azure/sentinel/datalake/notebooks#select-the-appropriate-runtime-pool).
7. Run cells sequentially or modify parameters as needed.
8. Review outputs — each notebook includes **schema previews, diagrams, and sample rows** to guide validation. The mermaid diagrams are only rendered in VS Code and GitHub.

---

## 📖 Structure

- **`Password Spray/`**  
  End-to-end pipeline for detecting password spray attacks in Microsoft Entra ID `SigninLogs`.  
  Includes:

  - `data_backfill_setup` → historical backfill of summary & stats tables
  - `signinlogs_summary_and_stats_daily` → daily rollups for efficiency
  - `password_spray_features` → recurring feature engineering with spray score.

---

## 🏗️ Notebook Index Diagram

```
📓 notebooks/
└── 📁 Password Spray/
    ├── 📓 00_data_backfill_setup.ipynb          → Historical Backfill
    ├── 📓 01_signinlogs_summary_and_stats_daily.ipynb → Daily Rollups
    └── 📓 02_password_spray_features.ipynb      → Recurring Feature Engineering
```

## 🧩 General Design Principles

- **Separation of Concerns** → Each notebook handles a focused task (backfill, daily summaries, features).
- **Reusability** → Parameters (date ranges, table names, fields) are modular for easy customization.
- **Cost Efficiency** → Long lookbacks use compact summary tables; frequent runs only scan fresh deltas.
- **Analyst-First Outputs** → All tables are structured for alerts, dashboards, and investigations.

---

## 📂 Output Tables

While each subfolder README describes outputs in detail, the common pattern is:

- **Daily Rollups** → Compact summary tables to support efficient queries.
- **Feature Tables** → Enriched datasets with scoring/labels for detections.
- **Stats Tables** → Global metrics for KPI dashboards and baselines.

---

## 📌 Next Steps

- Explore the `Password Spray/` folder for a complete example pipeline.
- Extend with new detection scenarios for Sentinel data lake.
- Contribute additional notebooks following the same modular structure.
