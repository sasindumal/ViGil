import json

path = 'f:/ViGil/cpg_train_evaluate.ipynb'
with open(path, 'r', encoding='utf-8') as f:
    nb = json.load(f)

for cell in nb['cells']:
    if cell['cell_type'] == 'code' and any('Evaluating on TEST SET' in line for line in cell['source']):
        source = cell['source']
        for i, line in enumerate(source):
            if 'with autocast(enabled=USE_AMP):' in line:
                source[i]   = '        with autocast(enabled=USE_AMP):\n'
                source[i+1] = '            logits = model(\n'
                source[i+2] = '                batch_data.x, batch_data.edge_index,\n'
                source[i+3] = '                batch_data.node_types, batch_data.edge_types, batch_idx\n'
                source[i+4] = '            )\n'

with open(path, 'w', encoding='utf-8') as f:
    json.dump(nb, f, indent=1)
