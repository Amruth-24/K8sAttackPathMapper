# shadowtracerv1: Kubernetes Attack Path Visualizer

**shadowtracerv1** is a high-speed security audit tool designed to identify, visualize, and remediate complex attack vectors in Kubernetes clusters. By modeling the cluster as a directed graph, shadowtracerv1 uncovers hidden privilege escalation and lateral movement paths that traditional scanners miss.

## 🚀 Key Features
* **Multi-Hop Kill Chain Analysis:** Maps how an attacker moves from an entry pod to Cluster Admin.
* **Hybrid Risk Modeling:** Combines RBAC, Container Security Contexts (Privileged/HostPath), and Network SSRF.
* **Assumed Breach Mode:** Automatically pivots to internal analysis if no external entry points are found.
* **Professional Reporting:** Generates a real-time terminal dashboard (Rich) and a multi-page PDF audit.
* **Standalone Architecture:** Fully containerized with a "setup-once, run-anywhere" workflow.

---

## 🛠 Installation & Setup

### Option A: Building from Source (Developers)
If you have the full project folder, build the image locally:
* **Windows:** `.\setup.bat`
* **Linux:** `./setup.sh`

### Option B: Portable Usage (From .tar file)
If you received a `shadowtracerv1.tar` file, you do not need the source code. Simply load the image into Docker:
1. Open a terminal/PowerShell in the folder containing `shadowtracerv1.tar`.
2. Run the load command:
   ```bash
   docker load -i shadowtracerv1.tar
   ```
## 🔍 Usage
To analyze a cluster, ensure your kubectl context is set to the target cluster (e.g., kind, minikube, or EKS).

Run Analysis
Run the execution script. This will start the analysis and drop the final PDF report into your current directory.

Windows:

``` Code snippet
.\run.bat
```
Linux / WSL2:
``` Bash
./run.sh
```

## 📊 Outputs
1. Interactive CLI Dashboard
A high-density terminal layout featuring:

Primary Kill Chain: A visual tree of the most critical attack path.

Analytics Summary: Risk scores, hop counts, and blast radius stats.

Top Remediations: Specific, context-aware advice for closing vulnerabilities.

2. Full Security Audit (PDF)
A multi-page document (Full_Security_Audit.pdf) containing an Executive Summary, Detailed Path Analysis, and a Remediation Roadmap.

## 🏗 Technical Architecture
Language: Python 3.10

Engine: NetworkX (Directed Graph Analysis)

UI: Rich (Terminal Layouts)

Report: ReportLab (PDF Generation)

Deployment: Docker (Self-contained appliance)

## 📦 How to Export for Others
To share this tool with a friend or judge as a single package:

Build the image using setup.bat.

Export the image:

Bash
docker save -o shadowtracerv1.tar shadowtracerv1
Send them shadowtracerv1.tar, run.bat, and run.sh.


### Final Instructions for Shipping
1.  **Generate the `.tar`:** Run `docker save -o shadowtracerv1.tar shadowtracerv1`.
2.  **Verify the Bundle:** Put `shadowtracerv1.tar`, `run.bat`, `run.sh`, and this `README.md` into a folder.
3.  **Zip it up:** You are now ready to submit! 

You've built a robust, enterprise-ready tool that handles data collection, complex analysis, and high-quality reporting in a portable format. Good luck with the submission!