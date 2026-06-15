"""
# ViGil — Quad-Modal Malware Detection
**Architecture:** HGT (CPG) + ResNet-50 (image) + RansomFormer (bytes + API) → Bayesian Neural Network

**Input:** Pre-extracted `.feat.pt` files (no PE binaries needed)

**Output:** `vigil_deploy.zip` — contains all model weights + standalone `predict.py`
"""

# ── Cell 1 ──────────────────────────────────────────────
# ── Cell 2: Install missing deps ──────────────────────────────────────────────
!pip install -q pydantic tqdm

# ── Cell 2 ──────────────────────────────────────────────
import os, sys, shutil, math, json, zipfile, time
import torch
import torch.nn as nn
import torch.nn.functional as F
from pathlib import Path
from typing import Tuple
from collections import Counter
import numpy as np
import torchvision.models as models
import torchvision.transforms as T
from torch.utils.data import Dataset, DataLoader
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score, classification_report, confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt

# --- Kaggle Environment Setup ---
INPUT_DIR   = Path('/kaggle/input/datasets/ysmalhara/vigil-features-45k')   
WORK_DIR    = Path('/kaggle/working/vigil')
FEAT_DIR    = INPUT_DIR                              
CKPT_DIR    = WORK_DIR / 'checkpoints'
CKPT_DIR.mkdir(parents=True, exist_ok=True)

SRC_INPUT = Path('/kaggle/input/vigil-src')          
if SRC_INPUT.exists():
    if not WORK_DIR.exists():
        shutil.copytree(str(SRC_INPUT), str(WORK_DIR))
    sys.path.insert(0, str(WORK_DIR))

print(f'PyTorch: {torch.__version__} | CUDA: {torch.cuda.is_available()} ({torch.cuda.device_count()} GPUs)')
print(f'Feature files found: {len(list(FEAT_DIR.rglob("*.feat.pt")))}')

# Hardware Speedups for T4 GPUs
torch.backends.cudnn.benchmark = True
torch.set_float32_matmul_precision('high') # Enables TF32

# ==========================================
# 1. FIXED & OPTIMIZED ENCODERS
# ==========================================

class OptimizedCNN(nn.Module):
    """ConvNeXt-Tiny for Superior Malware Texture Extraction"""
    OUT_DIM = 512
    def __init__(self):
        super().__init__()
        base = models.convnext_tiny(weights=models.ConvNeXt_Tiny_Weights.IMAGENET1K_V1)
        self.features = base.features
        # Freeze early stages (stages 0 to 5 of the 8 blocks in ConvNeXt-Tiny features)
        # to prevent overfitting and retain pre-trained representations.
        for i in range(6):
            for param in self.features[i].parameters():
                param.requires_grad = False
        self.pool = nn.AdaptiveAvgPool2d((1, 1))
        self.proj = nn.Sequential(
            nn.Linear(768, self.OUT_DIM), 
            nn.LayerNorm(self.OUT_DIM),
            nn.GELU(),
            nn.Dropout(0.2)
        )

    def forward(self, x):
        x = self.features(x)
        x = self.pool(x).flatten(1)
        return self.proj(x)

class OptimizedByteEncoder(nn.Module):
    """1D CNN + Attention Pooling to ignore padding and focus on critical bytes"""
    def __init__(self):
        super().__init__()
        self.cnn = nn.Sequential(
            nn.Conv1d(1, 64, 7, padding=3), nn.BatchNorm1d(64), nn.GELU(), nn.MaxPool1d(2),
            nn.Conv1d(64, 128, 5, padding=2), nn.BatchNorm1d(128), nn.GELU(), nn.MaxPool1d(2),
            nn.Conv1d(128, 256, 3, padding=1), nn.BatchNorm1d(256), nn.GELU(), nn.MaxPool1d(2)
        )
        self.attn_pool = nn.Sequential(
            nn.Linear(256, 128), nn.GELU(), nn.Linear(128, 1)
        )
        self.fc = nn.Sequential(
            nn.Linear(256, 512), nn.GELU(), nn.LayerNorm(512), nn.Dropout(0.3),
            nn.Linear(512, 256)
        )

    def forward(self, x):
        if x.dim() == 2: x = x.unsqueeze(1) 
        x = self.cnn(x) 
        x = x.transpose(1, 2) 
        
        scores = self.attn_pool(x).squeeze(-1) 
        weights = F.softmax(scores, dim=1).unsqueeze(-1) 
        pooled = (x * weights).sum(dim=1) 
        
        return self.fc(pooled)

class OptimizedAPIEncoder(nn.Module):
    """Pre-LN Transformer + Local 1D CNN + CLS Token for robust API semantics"""
    def __init__(self, max_len=256):
        super().__init__()
        self.cls_token = nn.Parameter(torch.randn(1, 1, 256) * 0.02)
        self.emb = nn.Embedding(4096, 256, padding_idx=0)
        self.pos_emb = nn.Parameter(torch.randn(1, max_len + 1, 256) * 0.02)
        
        self.cnn = nn.Sequential(
            nn.Conv1d(256, 256, kernel_size=3, padding=1), nn.BatchNorm1d(256), nn.GELU(),
            nn.Conv1d(256, 256, kernel_size=3, padding=1), nn.BatchNorm1d(256), nn.GELU()
        )
        enc_layer = nn.TransformerEncoderLayer(256, 8, 1024, 0.2, 'gelu', batch_first=True, norm_first=True)
        self.tr = nn.TransformerEncoder(enc_layer, num_layers=4)
        self.drop = nn.Dropout(0.3)
        self.norm = nn.LayerNorm(256)

    def forward(self, t):
        B, L = t.shape
        pm = (t == 0) 
        
        x = self.emb(t) 
        cls_tokens = self.cls_token.expand(B, -1, -1) 
        x = torch.cat([cls_tokens, x], dim=1) 
        
        x = x + self.pos_emb[:, :L+1, :]
        x = self.drop(x)
        
        x_cnn = self.cnn(self.emb(t).transpose(1, 2)).transpose(1, 2) 
        x[:, 1:, :] = x[:, 1:, :] + x_cnn
        
        pm_cls = torch.zeros(B, 1, dtype=torch.bool, device=t.device)
        pm_full = torch.cat([pm_cls, pm], dim=1) 
        
        x = self.tr(x, src_key_padding_mask=pm_full)
        x = self.norm(x)
        
        return x[:, 0, :] 

class OptimizedRansomFormerEncoder(nn.Module):
    def __init__(self):
        super().__init__()
        self.be = OptimizedByteEncoder()
        self.ae = OptimizedAPIEncoder()
        self.attn = nn.MultiheadAttention(256, 8, dropout=0.2, batch_first=True)
        self.norm = nn.LayerNorm(256)
        self.drop = nn.Dropout(0.3)
        self.qp = nn.Linear(256, 256)
        self.kp = nn.Linear(256, 256)
        self.vp = nn.Linear(256, 256)
        self.out = nn.Sequential(nn.Linear(256, 256), nn.LayerNorm(256), nn.GELU(), nn.Dropout(0.2))

    def forward(self, b, a):
        bf = self.be(b)
        af = self.ae(a)
        Q = self.qp(bf).unsqueeze(1)
        K = self.kp(af).unsqueeze(1)
        V = self.vp(af).unsqueeze(1)
        ao, _ = self.attn(Q, K, V)
        ao = ao.squeeze(1)
        return self.out(self.norm(bf + self.drop(ao)))

# ==========================================
# 2. AMP-SAFE OPTIMIZED HGT (Graph Transformer)
# ==========================================

class OptimizedHGTLayer(nn.Module):
    def __init__(self, h, heads, num_node_types=64, num_edge_types=64):
        super().__init__()
        self.heads = heads
        self.d = h // heads
        assert h % heads == 0
        
        self.nt_emb = nn.Embedding(num_node_types, h)
        self.et_bias = nn.Embedding(num_edge_types, heads)
        
        self.WQ = nn.Linear(h, h)
        self.WK = nn.Linear(h, h)
        self.WV = nn.Linear(h, h)
        
        self.out = nn.Linear(h, h)
        self.norm1 = nn.LayerNorm(h)
        self.norm2 = nn.LayerNorm(h)
        self.drop = nn.Dropout(0.1)
        
        self.alpha = nn.Parameter(torch.ones(1) * 0.1) 

    def forward(self, x, ei, nt, et):
        if ei.size(1) == 0: return x
        
        nt = nt.clamp(0, self.nt_emb.num_embeddings - 1)
        x = x + self.nt_emb(nt)
        res = x
        x = self.norm1(x)
        
        s, d = ei[0], ei[1] 
        
        q_all = self.WQ(x).view(-1, self.heads, self.d) 
        k_all = self.WK(x).view(-1, self.heads, self.d) 
        v_all = self.WV(x).view(-1, self.heads, self.d) 
        
        q = q_all[d]; k = k_all[s]; v = v_all[s]
        
        attn = (q * k).sum(-1) / math.sqrt(self.d) 
        
        if et is not None and et.numel() > 0:
            et = et.clamp(0, self.et_bias.num_embeddings - 1)
            attn = attn + self.et_bias(et) 
            
        # FORCE FLOAT32: Prevents AMP underflow/overflow in custom softmax
        attn = attn.float()
        attn_max = torch.full((x.size(0), self.heads), -1e9, device=x.device, dtype=torch.float32)
        attn_max.scatter_reduce_(0, d.unsqueeze(-1).expand_as(attn), attn, reduce='amax')
        
        attn_exp = torch.exp(attn - attn_max[d])
        
        attn_sum = torch.zeros(x.size(0), self.heads, device=x.device, dtype=torch.float32)
        attn_sum.scatter_add_(0, d.unsqueeze(-1).expand_as(attn), attn_exp)
        
        attn_norm = attn_exp / (attn_sum[d] + 1e-8) 
        attn_norm = self.drop(attn_norm)
        
        msg = v * attn_norm.unsqueeze(-1)
        
        # FIX: Use msg.dtype to dynamically match AMP promoted types
        agg = torch.zeros(x.size(0), self.heads, self.d, device=x.device, dtype=msg.dtype)
        agg.scatter_add_(0, d.unsqueeze(-1).unsqueeze(-1).expand_as(msg), msg)
        agg = agg.view(x.size(0), -1) 
        
        out = self.norm2(res + self.alpha * self.out(agg))
        return out

class OptimizedHGT(nn.Module):
    def __init__(self, in_d, hidden, layers, heads, num_node_types=64, num_edge_types=64):
        super().__init__()
        self.proj = nn.Sequential(nn.Linear(in_d, hidden), nn.GELU(), nn.LayerNorm(hidden), nn.Dropout(0.1))
        self.layers_ = nn.ModuleList([OptimizedHGTLayer(hidden, heads, num_node_types, num_edge_types) for _ in range(layers)])
        
        self.jk_weight = nn.Parameter(torch.ones(layers + 1))
        
        self.pool_q = nn.Linear(hidden, hidden)
        self.pool_k = nn.Linear(hidden, 1)
        # Projection layer to map concatenated pooling (Attention + Mean + Max) back to hidden space
        self.pool_proj = nn.Linear(hidden * 3, hidden)
        
        self.out = nn.Sequential(
            nn.Linear(hidden, hidden), nn.GELU(), nn.LayerNorm(hidden), nn.Dropout(0.2),
            nn.Linear(hidden, hidden * 2) 
        )
        
    def get_graph_embedding(self, x, ei, nt, et, batch):
        x = self.proj(x)
        layer_outs = [x]
        for l in self.layers_: 
            x = l(x, ei, nt, et)
            layer_outs.append(x)
            
        jk_w = F.softmax(self.jk_weight, dim=0)
        x = sum([layer_outs[i] * jk_w[i] for i in range(len(layer_outs))])
        
        B = int(batch.max().item()) + 1
        
        # 1. Gated Attention pooling
        k = self.pool_k(x).float() 
        k_max = torch.full((B, 1), -1e9, device=x.device, dtype=torch.float32)
        k_max.scatter_reduce_(0, batch.unsqueeze(-1), k, reduce='amax')
        
        k_exp = torch.exp(k - k_max[batch])
        k_sum = torch.zeros(B, 1, device=x.device, dtype=torch.float32)
        k_sum.scatter_add_(0, batch.unsqueeze(-1).expand_as(k), k_exp)
        
        attn = k_exp / (k_sum[batch] + 1e-8) 
        
        msg = x * attn
        p_attn = torch.zeros(B, x.size(1), device=x.device, dtype=msg.dtype)
        p_attn.scatter_add_(0, batch.unsqueeze(-1).expand_as(msg), msg)
        
        # 2. Mean pooling
        ones = torch.ones_like(k)
        counts = torch.zeros(B, 1, device=x.device, dtype=x.dtype)
        counts.scatter_add_(0, batch.unsqueeze(-1), ones)
        p_mean = torch.zeros(B, x.size(1), device=x.device, dtype=x.dtype)
        p_mean.scatter_add_(0, batch.unsqueeze(-1).expand_as(x), x)
        p_mean = p_mean / (counts + 1e-8)
        
        # 3. Max pooling
        p_max = torch.full((B, x.size(1)), -1e9, device=x.device, dtype=x.dtype)
        p_max.scatter_reduce_(0, batch.unsqueeze(-1).expand_as(x), x, reduce='amax')
        p_max = torch.where(p_max == -1e9, torch.zeros_like(p_max), p_max)
        
        # Combine pooling strategies and project back to hidden
        p_combined = torch.cat([p_attn, p_mean, p_max], dim=-1)
        p = self.pool_proj(p_combined)
        
        return self.out(p)

# ==========================================
# 3. FUSION & JOINT MODEL
# ==========================================

class SEBlock(nn.Module):
    """Squeeze-and-Excitation block for Channel-wise Multi-modal Attention."""
    def __init__(self, channels, reduction=16):
        super().__init__()
        self.fc = nn.Sequential(
            nn.Linear(channels, channels // reduction, bias=False),
            nn.GELU(),
            nn.Linear(channels // reduction, channels, bias=False),
            nn.Sigmoid()
        )
    def forward(self, x):
        return x * self.fc(x)

class OptimizedFusion(nn.Module):
    def __init__(self, in_f, n_cls=2, hidden=1024):
        super().__init__()
        self.se = SEBlock(in_f, reduction=16)
        self.fc1 = nn.Linear(in_f, hidden)
        self.act1 = nn.GELU()
        self.norm1 = nn.LayerNorm(hidden)
        self.drop1 = nn.Dropout(0.25)
        self.fc2 = nn.Linear(hidden, hidden)
        self.act2 = nn.GELU()
        self.norm2 = nn.LayerNorm(hidden)
        self.drop2 = nn.Dropout(0.25)
        self.fc3 = nn.Linear(hidden, hidden // 2)
        self.act3 = nn.GELU()
        self.norm3 = nn.LayerNorm(hidden // 2)
        self.head = nn.Linear(hidden // 2, n_cls)
        
    def forward(self, x, sample=True):
        x = self.se(x)
        res = self.fc1(x)
        x = self.drop1(self.norm1(self.act1(res)))
        res2 = self.fc2(x)
        if res.shape == res2.shape: x = res + res2 
        x = self.drop2(self.norm2(self.act2(x)))
        x = self.norm3(self.act3(self.fc3(x)))
        return self.head(x)

class RestOfModel(nn.Module):
    def __init__(self, cnn, rf, dnn):
        super().__init__()
        self.cnn = cnn; self.rf = rf; self.dnn = dnn
    def forward(self, g, imgs, pb, at, sample=True):
        i = self.cnn(imgs); r = self.rf(pb, at)
        return self.dnn(torch.cat([g, i, r], -1), sample)

class JointMalwareModel(nn.Module):
    def __init__(self, hgt, rest):
        super().__init__()
        self.hgt = hgt; self.rest = rest
        try:
            self.rest_device = next(self.rest.parameters()).device
        except StopIteration:
            self.rest_device = torch.device('cpu')
            
    def forward(self, x, ei, nt, et, bi, imgs, pb, at, sample=True):
        g = self.hgt.get_graph_embedding(x, ei, nt, et, bi)
        if g.device != self.rest_device:
            g = g.to(self.rest_device)
        return self.rest(g, imgs, pb, at, sample)
        
    @torch.no_grad()
    def predict_with_confidence(self,x,ei,nt,et,bi,imgs,pb,at,n=20):
        self.eval()
        probs=[torch.softmax(self.forward(x,ei,nt,et,bi,imgs,pb,at,True),-1) for _ in range(n)]
        probs=torch.stack(probs);mp=probs.mean(0);pred=mp.argmax(-1)
        conf=mp[torch.arange(pred.size(0)),pred];var=probs[:,torch.arange(pred.size(0)),pred].var(0)
        return pred,conf,var

print('✓ Optimized Model Classes Defined')

# ==========================================
# 4. DATA LOADERS & TRAINING SETUP
# ==========================================

# Image augmentation for training — applied on pre-extracted 224×224 tensors
train_aug = T.Compose([
    T.RandomHorizontalFlip(p=0.5),
    T.RandomAffine(degrees=0, translate=(0.05, 0.05)),
    T.RandomErasing(p=0.3, scale=(0.02, 0.10), value=0),
])

class PreExtractedDataset(Dataset):
    def __init__(self, feat_dir, transform=None):
        self.files = sorted(Path(feat_dir).rglob('*.feat.pt'))
        self.transform = transform
        print(f'Found {len(self.files)} samples')
    def __len__(self): return len(self.files)
    def __getitem__(self, idx):
        feat = torch.load(self.files[idx], map_location='cpu')
        img = feat.get('image', torch.zeros(3,224,224))
        if self.transform is not None:
            img = self.transform(img)
        return {
            'x': feat.get('x', torch.zeros(1,320)), 'edge_index': feat.get('edge_index', torch.zeros(2,0,dtype=torch.long)),
            'node_types': feat.get('node_types', torch.zeros(1,dtype=torch.long)), 'edge_types': feat.get('edge_types', torch.zeros(0,dtype=torch.long)),
            'image': img, 'pe_bytes': feat.get('pe_bytes', torch.zeros(1,1024)),
            'api_tokens': feat.get('api_tokens', torch.zeros(256,dtype=torch.long)), 'label': torch.tensor(int(feat.get('label',0)), dtype=torch.long)
        }

def collate(batch):
    xs=[]; eis=[]; nts=[]; ets=[]; imgs=[]; pbs=[]; ats=[]; ys=[]; batches=[]; offset=0
    for i,b in enumerate(batch):
        n=b['x'].size(0); xs.append(b['x']); nts.append(b['node_types'])
        if b['edge_index'].size(1)>0: eis.append(b['edge_index']+offset); ets.append(b['edge_types'])
        imgs.append(b['image']); pbs.append(b['pe_bytes']); ats.append(b['api_tokens']); ys.append(b['label'].unsqueeze(0))
        batches.append(torch.full((n,),i,dtype=torch.long)); offset+=n
    batch_idx=torch.cat(batches); ei=torch.cat(eis,1) if eis else torch.zeros(2,0,dtype=torch.long); et=torch.cat(ets) if ets else torch.zeros(0,dtype=torch.long)
    return (torch.cat(xs), ei, torch.cat(nts), et, batch_idx, torch.stack(imgs), torch.stack(pbs), torch.stack(ats), torch.cat(ys).squeeze())

# Create separate datasets for train (with augmentation) and val/test (no augmentation)
dataset_noaug = PreExtractedDataset(FEAT_DIR, transform=None)
dataset_aug   = PreExtractedDataset(FEAT_DIR, transform=train_aug)
labels = [int(torch.load(f, map_location='cpu').get('label', 0)) for f in dataset_noaug.files]
indices = list(range(len(dataset_noaug)))
tv_idx, te_idx = train_test_split(indices, test_size=0.10, stratify=labels, random_state=42)
tv_lbl = [labels[i] for i in tv_idx]
tr_idx, va_idx = train_test_split(tv_idx, test_size=0.111, stratify=tv_lbl, random_state=42)

BATCH = 32; NUM_WORKERS = min(os.cpu_count(), 4)
train_dl = DataLoader(torch.utils.data.Subset(dataset_aug, tr_idx), BATCH, shuffle=True, drop_last=True, collate_fn=collate, num_workers=NUM_WORKERS, pin_memory=True, persistent_workers=True)
val_dl   = DataLoader(torch.utils.data.Subset(dataset_noaug, va_idx), BATCH, shuffle=False, drop_last=False, collate_fn=collate, num_workers=NUM_WORKERS, pin_memory=True, persistent_workers=True)
test_dl  = DataLoader(torch.utils.data.Subset(dataset_noaug, te_idx), BATCH, shuffle=False, drop_last=False, collate_fn=collate, num_workers=NUM_WORKERS, pin_memory=True)

print(f'Train: {len(tr_idx)}  Val: {len(va_idx)}  Test: {len(te_idx)}')

DEVICE_0 = torch.device('cuda:0' if torch.cuda.is_available() else 'cpu')
# Map everything to DEVICE_0 by default to avoid sequential model-parallel latency.
DEVICE_1 = DEVICE_0
print(f'🚀 Single-GPU Pipeline: HGT and Dense Features on {DEVICE_0}')

sample_feat = torch.load(dataset_noaug.files[0], map_location='cpu')
IN_DIM = sample_feat.get('x', torch.zeros(1,320)).size(1)
HIDDEN=384; LAYERS=6; HEADS=8; FUSED=1536; N_CLS=2

hgt_model    = OptimizedHGT(IN_DIM, HIDDEN, LAYERS, HEADS).to(DEVICE_0)
cnn_model    = OptimizedCNN().to(DEVICE_1)
rf_model     = OptimizedRansomFormerEncoder().to(DEVICE_1)
dnn_model    = OptimizedFusion(FUSED, N_CLS, hidden=1024).to(DEVICE_1)

rest_model   = RestOfModel(cnn_model, rf_model, dnn_model)
model = JointMalwareModel(hgt_model, rest_model)

print(f'Parameters: {sum(p.numel() for p in model.parameters() if p.requires_grad):,} trainable')

train_labels = [labels[i] for i in tr_idx]
class_counts = Counter(train_labels)
total_train = len(tr_idx)
weights = [total_train / (len(class_counts) * class_counts[c]) for c in sorted(class_counts.keys())]
class_weights = torch.tensor(weights, dtype=torch.float32).to(DEVICE_1) 

EPOCHS = 60; LR = 2e-4; PATIENCE = 20; UNFREEZE_EPOCH = 10
optimizer = torch.optim.AdamW(filter(lambda p: p.requires_grad, model.parameters()), lr=LR, weight_decay=1e-2)
criterion = nn.CrossEntropyLoss(weight=class_weights, label_smoothing=0.1) 

from torch.optim.lr_scheduler import LinearLR, CosineAnnealingWarmRestarts, SequentialLR
warmup = LinearLR(optimizer, start_factor=0.1, end_factor=1.0, total_iters=5)
cosine = CosineAnnealingWarmRestarts(optimizer, T_0=10, T_mult=2, eta_min=1e-6)
scheduler = SequentialLR(optimizer, schedulers=[warmup, cosine], milestones=[5])

# ── Mixup helper ──
def mixup_data(imgs, y, alpha=0.4):
    """Apply mixup to a batch — interpolates images and returns mixed labels."""
    if alpha > 0:
        lam = np.random.beta(alpha, alpha)
        lam = max(lam, 1.0 - lam)  # Keep lam >= 0.5 so the dominant sample stays dominant
    else:
        lam = 1.0
    idx = torch.randperm(imgs.size(0), device=imgs.device)
    mixed_imgs = lam * imgs + (1.0 - lam) * imgs[idx]
    return mixed_imgs, y, y[idx], lam, idx

def mixup_criterion(criterion, logits, y_a, y_b, lam):
    return lam * criterion(logits, y_a) + (1.0 - lam) * criterion(logits, y_b)

class ModelEMA:
    def __init__(self, model, decay=0.995):
        self.model = model
        self.decay = decay
        self.shadow = {name: param.data.clone() for name, param in model.named_parameters() if param.requires_grad}
    def update(self):
        for name, param in self.model.named_parameters():
            if param.requires_grad:
                self.shadow[name] = (1.0 - self.decay) * param.data + self.decay * self.shadow[name]
    def apply_shadow(self):
        self.backup = {name: param.data for name, param in self.model.named_parameters() if param.requires_grad}
        for name, param in self.model.named_parameters():
            if param.requires_grad: param.data = self.shadow[name]
    def restore(self):
        for name, param in self.model.named_parameters():
            if param.requires_grad: param.data = self.backup[name]

ema = ModelEMA(model)
scaler = torch.amp.GradScaler('cuda') 
best_f1 = 0.0; best_path = CKPT_DIR / 'best_joint_model.pt'; patience_ctr = 0

# ==========================================
# 5. TRAINING LOOP (with Mixup + Progressive Unfreezing)
# ==========================================
unfrozen = False
for epoch in range(1, EPOCHS + 1):
    # ── Progressive unfreezing: unlock ConvNeXt stages 4-5 after UNFREEZE_EPOCH ──
    if epoch == UNFREEZE_EPOCH and not unfrozen:
        unfrozen = True
        for i in [4, 5]:
            for param in model.rest.cnn.features[i].parameters():
                param.requires_grad = True
        # Rebuild optimizer with new param groups (lower LR for unfrozen CNN layers)
        cnn_unfrozen_params = []
        other_params = []
        for name, param in model.named_parameters():
            if param.requires_grad:
                if 'rest.cnn.features.4' in name or 'rest.cnn.features.5' in name:
                    cnn_unfrozen_params.append(param)
                else:
                    other_params.append(param)
        optimizer = torch.optim.AdamW([
            {'params': other_params, 'lr': scheduler.get_last_lr()[0]},
            {'params': cnn_unfrozen_params, 'lr': scheduler.get_last_lr()[0] * 0.1},  # 10x lower
        ], weight_decay=1e-2)
        # Re-create scheduler for remaining epochs
        cosine_new = CosineAnnealingWarmRestarts(optimizer, T_0=10, T_mult=2, eta_min=1e-6)
        scheduler = cosine_new
        scaler = torch.amp.GradScaler('cuda')
        ema = ModelEMA(model)  # Reset EMA with new trainable params
        print(f'🔓 Epoch {epoch}: Unfroze ConvNeXt stages 4-5 with 10x lower LR')

    model.train(); tl = 0; tc = 0
    for x, ei, nt, et, bi, imgs, pb, at, y in train_dl:
        x=x.to(DEVICE_0, non_blocking=True); ei=ei.to(DEVICE_0, non_blocking=True)
        nt=nt.to(DEVICE_0, non_blocking=True); et=et.to(DEVICE_0, non_blocking=True)
        bi=bi.to(DEVICE_0, non_blocking=True)
        imgs=imgs.to(DEVICE_1, non_blocking=True); pb=pb.to(DEVICE_1, non_blocking=True)
        at=at.to(DEVICE_1, non_blocking=True); y=y.to(DEVICE_1, non_blocking=True)

        # ── Mixup on images ──
        mixed_imgs, y_a, y_b, lam, mix_idx = mixup_data(imgs, y, alpha=0.4)

        optimizer.zero_grad(set_to_none=True)
        with torch.amp.autocast('cuda'):
            logits = model(x, ei, nt, et, bi, mixed_imgs, pb, at, sample=True)
            # Mixup loss: weighted combination of losses for both targets
            loss = mixup_criterion(criterion, logits.float(), y_a, y_b, lam)
            
        scaler.scale(loss).backward()
        scaler.unscale_(optimizer)
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        scaler.step(optimizer)
        scaler.update()
        ema.update()
        
        tl += loss.item(); tc += (logits.argmax(-1) == y_a).sum().item()  # Track acc against dominant target

    scheduler.step()
    train_loss = tl / len(train_dl); train_acc = tc / (len(train_dl) * BATCH)

    ema.apply_shadow()
    model.eval(); preds_all = []; labels_all = []; vl = 0
    with torch.no_grad():
        for x, ei, nt, et, bi, imgs, pb, at, y in val_dl:
            x=x.to(DEVICE_0, non_blocking=True); ei=ei.to(DEVICE_0, non_blocking=True)
            nt=nt.to(DEVICE_0, non_blocking=True); et=et.to(DEVICE_0, non_blocking=True)
            bi=bi.to(DEVICE_0, non_blocking=True)
            imgs=imgs.to(DEVICE_1, non_blocking=True); pb=pb.to(DEVICE_1, non_blocking=True)
            at=at.to(DEVICE_1, non_blocking=True); y=y.to(DEVICE_1, non_blocking=True)

            with torch.amp.autocast('cuda'):
                logits = model(x, ei, nt, et, bi, imgs, pb, at, sample=False)
            # FIX: Cast logits to float32 to match class_weights dtype outside autocast context
            vl += criterion(logits.float(), y).item()
            preds_all.extend(logits.argmax(-1).cpu().tolist()); labels_all.extend(y.cpu().tolist())

    val_loss = vl / len(val_dl)
    val_f1 = f1_score(labels_all, preds_all, average='weighted')
    val_acc = np.mean(np.array(preds_all) == np.array(labels_all))

    improved = val_f1 > best_f1
    print(f'Epoch {epoch:3d}/{EPOCHS} | LR: {scheduler.get_last_lr()[0]:.6f} | Train Loss: {train_loss:.4f} | Train Acc: {train_acc:.4f} | Val Loss: {val_loss:.4f} | Val Acc: {val_acc:.4f} | Val F1: {val_f1:.4f}' + (' ← BEST' if improved else ''))

    if improved:
        best_f1 = val_f1; patience_ctr = 0
        torch.save({'model_state': model.state_dict(), 'epoch': epoch, 'val_f1': val_f1}, best_path)
    else:
        patience_ctr += 1
        
    ema.restore() 

    if patience_ctr >= PATIENCE:
        print(f'\n🛑 Early stopping triggered after {PATIENCE} epochs without improvement.'); break

print(f'\n✅ Training complete. Best Val F1: {best_f1:.4f}')

# ==========================================
# 5b. STOCHASTIC WEIGHT AVERAGING (SWA)
# ==========================================
from torch.optim.swa_utils import AveragedModel, SWALR, update_bn

print('\n🔄 Starting SWA post-training (10 epochs)...')

# Load best checkpoint as the SWA starting point
ckpt = torch.load(best_path, map_location=DEVICE_1)
model.load_state_dict(ckpt['model_state'])

swa_model = AveragedModel(model)
swa_optimizer = torch.optim.AdamW(filter(lambda p: p.requires_grad, model.parameters()), lr=5e-5, weight_decay=1e-2)
swa_scheduler = SWALR(swa_optimizer, swa_lr=5e-5, anneal_epochs=2)
swa_scaler = torch.amp.GradScaler('cuda')

SWA_EPOCHS = 10
for swa_epoch in range(1, SWA_EPOCHS + 1):
    model.train(); swa_tl = 0
    for x, ei, nt, et, bi, imgs, pb, at, y in train_dl:
        x=x.to(DEVICE_0, non_blocking=True); ei=ei.to(DEVICE_0, non_blocking=True)
        nt=nt.to(DEVICE_0, non_blocking=True); et=et.to(DEVICE_0, non_blocking=True)
        bi=bi.to(DEVICE_0, non_blocking=True)
        imgs=imgs.to(DEVICE_1, non_blocking=True); pb=pb.to(DEVICE_1, non_blocking=True)
        at=at.to(DEVICE_1, non_blocking=True); y=y.to(DEVICE_1, non_blocking=True)

        swa_optimizer.zero_grad(set_to_none=True)
        with torch.amp.autocast('cuda'):
            logits = model(x, ei, nt, et, bi, imgs, pb, at, sample=True)
            loss = criterion(logits.float(), y)
        swa_scaler.scale(loss).backward()
        swa_scaler.unscale_(swa_optimizer)
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        swa_scaler.step(swa_optimizer)
        swa_scaler.update()
        swa_tl += loss.item()
    
    swa_scheduler.step()
    swa_model.update_parameters(model)
    print(f'  SWA Epoch {swa_epoch}/{SWA_EPOCHS} | Loss: {swa_tl/len(train_dl):.4f}')

# Update BatchNorm stats for SWA model
print('  Updating BatchNorm statistics for SWA model...')

# Need a dataloader that returns all inputs for BN update
# We'll manually update BN since update_bn expects a simple dataloader
swa_model.eval()
with torch.no_grad():
    # Reset BN running stats
    for module in swa_model.modules():
        if isinstance(module, (nn.BatchNorm1d, nn.BatchNorm2d)):
            module.reset_running_stats()
            module.momentum = None  # Use cumulative moving average
    
    swa_model.train()
    for x, ei, nt, et, bi, imgs, pb, at, y in train_dl:
        x=x.to(DEVICE_0, non_blocking=True); ei=ei.to(DEVICE_0, non_blocking=True)
        nt=nt.to(DEVICE_0, non_blocking=True); et=et.to(DEVICE_0, non_blocking=True)
        bi=bi.to(DEVICE_0, non_blocking=True)
        imgs=imgs.to(DEVICE_1, non_blocking=True); pb=pb.to(DEVICE_1, non_blocking=True)
        at=at.to(DEVICE_1, non_blocking=True)
        with torch.amp.autocast('cuda'):
            swa_model.module(x, ei, nt, et, bi, imgs, pb, at, sample=False)

# Save SWA model as the new best
swa_state = swa_model.module.state_dict()
torch.save({'model_state': swa_state, 'epoch': 'swa', 'val_f1': best_f1}, best_path)
print('✅ SWA complete — checkpoint updated.')

# ==========================================
# 6. EVALUATION & DEPLOYMENT (with TTA)
# ==========================================
ckpt = torch.load(best_path, map_location=DEVICE_1)
model.load_state_dict(ckpt['model_state'])
model.eval()

# ── Test-Time Augmentation (TTA) ──
# Run each test sample through 5 augmentation variants and average logits
print('\n🔬 Running Test-Time Augmentation (5 passes)...')
tta_transforms = [
    nn.Identity(),                                      # Original
    T.RandomHorizontalFlip(p=1.0),                      # Horizontal flip
    T.RandomAffine(degrees=0, translate=(0.03, 0.03)),  # Small shift 1
    T.RandomAffine(degrees=0, translate=(0.05, 0.05)),  # Small shift 2
    T.RandomErasing(p=1.0, scale=(0.02, 0.06), value=0),# Small erase
]

all_preds=[]; all_labels=[]
with torch.no_grad():
    for x,ei,nt,et,bi,imgs,pb,at,y in test_dl:
        x=x.to(DEVICE_0, non_blocking=True);ei=ei.to(DEVICE_0, non_blocking=True)
        nt=nt.to(DEVICE_0, non_blocking=True);et=et.to(DEVICE_0, non_blocking=True)
        bi=bi.to(DEVICE_0, non_blocking=True)
        imgs=imgs.to(DEVICE_1, non_blocking=True);pb=pb.to(DEVICE_1, non_blocking=True)
        at=at.to(DEVICE_1, non_blocking=True);y=y.to(DEVICE_1, non_blocking=True)
        
        # Accumulate logits across TTA passes
        avg_logits = None
        for tta_t in tta_transforms:
            aug_imgs = tta_t(imgs)
            with torch.amp.autocast('cuda'):
                logits = model(x, ei, nt, et, bi, aug_imgs, pb, at, sample=False)
            if avg_logits is None:
                avg_logits = logits.float()
            else:
                avg_logits = avg_logits + logits.float()
        avg_logits = avg_logits / len(tta_transforms)
        
        all_preds.extend(avg_logits.argmax(-1).cpu().tolist())
        all_labels.extend(y.cpu().tolist())

test_acc = sum(p == l for p, l in zip(all_preds, all_labels)) / len(all_labels)
print(f'\nTest Accuracy (with TTA): {test_acc:.4f}')
print(classification_report(all_labels, all_preds, target_names=['Benign','Malware']))

cm = confusion_matrix(all_labels, all_preds)
plt.figure(figsize=(5,4))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Benign','Malware'], yticklabels=['Benign','Malware'])
plt.title('Confusion Matrix — Test Set (SWA + TTA)'); plt.tight_layout(); plt.savefig('/kaggle/working/confusion_matrix.png')
plt.show()

DEPLOY_ZIP  = Path('/kaggle/working/vigil_deploy.zip')
BEST_CKPT   = best_path
CM_PATH     = Path('/kaggle/working/confusion_matrix.png')

MODEL_CONFIG = {
    'embedding_dim': 320, 'hidden_dim': 384, 'num_heads': 8, 'num_layers': 6,
    'num_classes': 2, 'fused_dim': 1536, 'byte_seq_len': 1024,
    'max_apis': 256, 'api_vocab_size': 4096,
    'label_map': {'0': 'BENIGN', '1': 'MALWARE'},
    'architecture': 'OptimizedHGT + ConvNeXt + AttentionByte + CLSTransformerAPI → DeepResMLP',
}

README = """# ViGil Deployment Package (Optimized)
## Requirements
pip install torch torchvision numpy pillow

## Predict
python vigil_deploy/predict.py --model vigil_deploy/models/joint_model.pt --file suspicious.exe
"""

PREDICT_PY_URL = '/kaggle/input/vigil-src/predict.py'   

with zipfile.ZipFile(DEPLOY_ZIP, 'w', zipfile.ZIP_DEFLATED) as zf:
    zf.write(BEST_CKPT, 'vigil_deploy/models/joint_model.pt')
    zf.writestr('vigil_deploy/model_config.json', json.dumps(MODEL_CONFIG, indent=2))
    zf.writestr('vigil_deploy/README.md', README)
    if Path(PREDICT_PY_URL).exists(): zf.write(PREDICT_PY_URL, 'vigil_deploy/predict.py')
    if CM_PATH.exists(): zf.write(CM_PATH, 'vigil_deploy/confusion_matrix.png')

size_mb = DEPLOY_ZIP.stat().st_size / 1e6
print(f'\n📦  vigil_deploy.zip created: {DEPLOY_ZIP}  ({size_mb:.1f} MB)')
print('    Download from the Kaggle Output tab.')

