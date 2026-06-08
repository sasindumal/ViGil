import json

path = 'f:/ViGil/cpg_train_evaluate.ipynb'
with open(path, 'r', encoding='utf-8') as f:
    nb = json.load(f)

# The cell source:
zip_code = [
    "# \u2500\u2500\u2500 Standalone Deployment Package \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n",
    "import zipfile\n",
    "import os\n",
    "\n",
    "zip_filename = 'deployment.zip'\n",
    "print(f'Creating standalone deployment package: {zip_filename}...')\n",
    "\n",
    "with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:\n",
    "    # Add prediction script\n",
    "    if os.path.exists('predict.py'):\n",
    "        zipf.write('predict.py')\n",
    "        print('  + Added predict.py')\n",
    "    \n",
    "    # Add the model\n",
    "    model_path = CHECKPOINT_DIR / 'final_model.pt'\n",
    "    if model_path.exists():\n",
    "        zipf.write(model_path, arcname='final_model.pt')\n",
    "        print('  + Added final_model.pt')\n",
    "        \n",
    "    # Add the uir directory\n",
    "    if os.path.exists('uir'):\n",
    "        for root, dirs, files in os.walk('uir'):\n",
    "            if '__pycache__' in root:\n",
    "                continue\n",
    "            for file in files:\n",
    "                if file.endswith('.pyc') or '.DS_Store' in file:\n",
    "                    continue\n",
    "                file_path = os.path.join(root, file)\n",
    "                zipf.write(file_path)\n",
    "        print('  + Added uir/ package')\n",
    "\n",
    "print(f'\\n\\u2705 Done! You can now use {zip_filename} on any machine.')\n"
]

already_added = any('Standalone Deployment Package' in "".join(c['source']) for c in nb['cells'] if c['cell_type'] == 'code')

if not already_added:
    nb['cells'].append({
        "cell_type": "markdown",
        "metadata": {},
        "source": [
            "---\n",
            "## 12. Build Standalone Deployment Zip\n",
            "\n",
            "Creates a `deployment.zip` containing `predict.py`, the `final_model.pt` weights, and the `uir` package. You can unzip this on any machine to run predictions without the full repository."
        ]
    })
    
    nb['cells'].append({
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": zip_code
    })
    
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(nb, f, indent=1)
    print("Added zip generation cell to notebook.")
else:
    print("Zip generation cell already exists.")
