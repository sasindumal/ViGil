import json
from pathlib import Path

def main():
    workspace_dir = Path(__file__).resolve().parents[1]
    notebook_path = workspace_dir / "traning_notebook" / "vigil.ipynb"
    script_path = workspace_dir / "traning_notebook" / "vigil_extracted.py"

    print(f"Reading script: {script_path}")
    with open(script_path, "r", encoding="utf-8") as f:
        script_lines = f.readlines()

    print(f"Reading notebook: {notebook_path}")
    with open(notebook_path, "r", encoding="utf-8") as f:
        notebook_data = json.load(f)

    # In vigil.ipynb, the third cell (index 2) contains the main training script.
    # Let's verify and update it.
    cells = notebook_data.get("cells", [])
    if len(cells) < 3:
        raise ValueError(f"Expected at least 3 cells in notebook, found {len(cells)}")
    
    target_cell = cells[2]
    print(f"Target cell type: {target_cell.get('cell_type')}")
    if target_cell.get("cell_type") != "code":
        raise ValueError("Expected the third cell to be of type 'code'")

    # Update the source of the target cell
    # Note: notebook line format expects each line to end with \n
    target_cell["source"] = script_lines
    
    # Clear outputs in the notebook to keep it clean and reduce file size
    target_cell["outputs"] = []
    target_cell["execution_count"] = None

    print(f"Saving updated notebook to: {notebook_path}")
    with open(notebook_path, "w", encoding="utf-8") as f:
        json.dump(notebook_data, f, indent=1)

    print("Successfully synchronized vigil_extracted.py to vigil.ipynb!")

if __name__ == "__main__":
    main()
