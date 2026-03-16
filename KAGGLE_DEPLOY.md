# 🚀 Deploy CPG Notebook to Kaggle

## Step 1: Create the Dataset

**Zip your project files locally:**

```bash
cd /Users/sasindumalhara/Shared/CPG
zip -r CPG_project.zip cpgs/ uir/ setup.py requirements.txt
```

1. Go to [kaggle.com/datasets](https://www.kaggle.com/datasets) → **New Dataset**
2. Upload `CPG_project.zip`, name it **`cpg-malware-dataset`**
3. Wait for processing to complete

> Your files will be at `/kaggle/input/cpg-malware-dataset/`

---

## Step 2: Create Kaggle Notebook

1. Go to [kaggle.com/code](https://www.kaggle.com/code) → **New Notebook**
2. Click **Add Data** (right sidebar) → search **`cpg-malware-dataset`** → **Add**
3. Set **Accelerator → GPU T4 x2** (or GPU P100)
4. Enable **Internet** in Settings (needed for `pip install`)

---

## Step 3: Add Setup Cell (First Cell)

Add this as the **very first code cell** before all other cells:

```python
import os, sys, shutil

# Copy project files to a writable directory (Kaggle input is read-only)
INPUT_DIR = '/kaggle/input/cpg-malware-dataset'
WORK_DIR  = '/kaggle/working/CPG'

if not os.path.exists(WORK_DIR):
    shutil.copytree(INPUT_DIR, WORK_DIR)

os.chdir(WORK_DIR)
sys.path.insert(0, WORK_DIR)

# Install missing dependencies
!pip install -q pydantic pylnk3

print(f"Working directory: {os.getcwd()}")
print(f"Files: {os.listdir('.')}")
```

---

## Step 4: Update Paths in Configuration Cell

In **Section 2 (Configuration)**, change the paths:

```python
CPG_DIR        = Path('/kaggle/working/CPG/cpgs')
CHECKPOINT_DIR = Path('/kaggle/working/checkpoints')
```

Everything else stays the same.

---

## Step 5: Run & Download

1. Click **Run All** or run cells sequentially
2. After training, outputs appear in the **Output** tab
3. Download `best_model.pt` and `final_model.pt` from there
4. Or click **Save Version** to create a reusable Kaggle dataset

---

## Quick Reference

| Item | Detail |
|------|--------|
| **GPU** | Always enable — HGT on CPU is very slow |
| **Read-only input** | That's why we copy to `/kaggle/working/` |
| **Pre-installed** | `torch`, `numpy`, `sklearn`, `matplotlib`, `seaborn` |
| **Need to install** | `pydantic`, `pylnk3` |
| **Session limit** | ~12h GPU / ~9h with internet |
| **Notebook features** | Train/Val/Test split, Early Stopping, LR Scheduler, Best Weights Restore |
