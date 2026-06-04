#!/usr/bin/env python3
"""
predict.py — Standalone ViGil Predictor

Run malware prediction on a PE file using a saved joint model checkpoint.
This script is SELF-CONTAINED — it does NOT require the `uir` package.
It includes all necessary model definitions inline.

Usage:
    python predict.py --model vigil_deploy/models/joint_model.pt \
                      --file  suspicious.exe [--samples 20]
"""

import sys
import json
import math
import argparse
from pathlib import Path

# ── Inline imports guard ──────────────────────────────────────────────────────
try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    import numpy as np
except ImportError:
    print("ERROR: torch and numpy are required.  pip install torch numpy")
    sys.exit(1)

try:
    from PIL import Image as PILImage
    import torchvision.transforms as transforms
    import torchvision.models as tv_models
    HAS_VISION = True
except ImportError:
    HAS_VISION = False

# Add potential paths to sys.path to find the `uir` package
for path in [
    Path(__file__).resolve().parent,
    Path(__file__).resolve().parent.parent,
    Path(__file__).resolve().parent / "src",
    Path("/Users/sasindumalhara/Workspace/ViGil"),
]:
    if (path / "uir").exists() and str(path) not in sys.path:
        sys.path.insert(0, str(path))

try:
    from uir.pipeline.processor import FileProcessor
    from uir.model.dataset import CPGDataset
    from uir.config import UIRConfig
    HAS_UIR = True
except ImportError:
    HAS_UIR = False

# ─────────────────────────────────────────────────────────────────────────────
# Inline model definitions (mirrors uir/model/ — no package needed)
# ─────────────────────────────────────────────────────────────────────────────

class BayesianLinear(nn.Module):
    def __init__(self, in_f, out_f, prior=0.1):
        super().__init__()
        self.prior = prior
        self.weight_mu  = nn.Parameter(torch.Tensor(out_f, in_f))
        self.weight_rho = nn.Parameter(torch.Tensor(out_f, in_f))
        self.bias_mu    = nn.Parameter(torch.Tensor(out_f))
        self.bias_rho   = nn.Parameter(torch.Tensor(out_f))
        nn.init.kaiming_uniform_(self.weight_mu, a=math.sqrt(5))
        nn.init.constant_(self.weight_rho, -3.0)
        fan_in = in_f; bound = 1/math.sqrt(fan_in)
        nn.init.uniform_(self.bias_mu, -bound, bound)
        nn.init.constant_(self.bias_rho, -3.0)

    def forward(self, x, sample=True):
        if sample:
            ws = torch.log1p(torch.exp(self.weight_rho))
            w  = self.weight_mu + ws * torch.randn_like(self.weight_mu)
            bs = torch.log1p(torch.exp(self.bias_rho))
            b  = self.bias_mu  + bs * torch.randn_like(self.bias_mu)
        else:
            w, b = self.weight_mu, self.bias_mu
        return F.linear(x, w, b)


class BayesianClassifier(nn.Module):
    def __init__(self, in_f, n_cls=2, hidden=256):
        super().__init__()
        self.fc1 = BayesianLinear(in_f, hidden); self.act = nn.GELU()
        self.fc2 = BayesianLinear(hidden, n_cls)
    def forward(self, x, sample=True):
        return self.fc2(self.act(self.fc1(x, sample)), sample)


class ResNetFeatureExtractor(nn.Module):
    OUT_DIM = 384
    def __init__(self):
        super().__init__()
        try:
            from torchvision.models import ResNet50_Weights
            bb = tv_models.resnet50(weights=None)
        except Exception:
            bb = tv_models.resnet50(pretrained=False)
        self.conv1=bb.conv1; self.bn1=bb.bn1; self.relu=bb.relu
        self.maxpool=bb.maxpool; self.layer1=bb.layer1; self.layer2=bb.layer2
        self.layer3=bb.layer3; self.layer4=bb.layer4
        self.avgpool   = nn.AdaptiveAvgPool2d((1,1))
        self.dropout   = nn.Dropout(0.2)
        self.projection= nn.Sequential(
            nn.Linear(2048, self.OUT_DIM), nn.LayerNorm(self.OUT_DIM), nn.GELU())
    def forward(self, x):
        x=self.conv1(x); x=self.bn1(x); x=self.relu(x); x=self.maxpool(x)
        x=self.layer1(x); x=self.layer2(x); x=self.layer3(x); x=self.layer4(x)
        x=self.avgpool(x).flatten(1); x=self.dropout(x)
        return self.projection(x)


class ByteEncoder(nn.Module):
    def __init__(self):
        super().__init__()
        self.conv1 = nn.Sequential(nn.Conv1d(1,64,5,padding=2),nn.BatchNorm1d(64),nn.ReLU(),nn.MaxPool1d(2))
        self.conv2 = nn.Sequential(nn.Conv1d(64,128,3,padding=1),nn.BatchNorm1d(128),nn.ReLU(),nn.MaxPool1d(2))
        self.pool  = nn.AdaptiveAvgPool1d(64)
        self.fc    = nn.Linear(128*64, 256); self.drop = nn.Dropout(0.2)
    def forward(self, x):
        x=self.conv1(x); x=self.conv2(x); x=self.pool(x)
        return self.fc(self.drop(x.flatten(1)))


class APIEncoder(nn.Module):
    def __init__(self):
        super().__init__()
        self.emb = nn.Embedding(4096, 256, padding_idx=0)
        enc = nn.TransformerEncoderLayer(256,8,512,0.2,"relu",batch_first=True)
        self.tr  = nn.TransformerEncoder(enc, num_layers=8)
        self.drop= nn.Dropout(0.2)
    def forward(self, t):
        pm = (t==0).clone(); pm[:,0]=False
        x  = self.drop(self.emb(t))
        x  = self.tr(x, src_key_padding_mask=pm)
        op = (~(t==0)).unsqueeze(-1).float()
        return (x*op).sum(1)/op.sum(1).clamp(min=1)


class RansomFormerEncoder(nn.Module):
    def __init__(self):
        super().__init__()
        self.byte_enc = ByteEncoder(); self.api_enc = APIEncoder()
        self.attn = nn.MultiheadAttention(256,8,dropout=0.2,batch_first=True)
        self.norm = nn.LayerNorm(256); self.drop = nn.Dropout(0.2)
        self.qp = nn.Linear(256,256); self.kp = nn.Linear(256,256); self.vp = nn.Linear(256,256)
        self.out = nn.Sequential(nn.Linear(256,256),nn.LayerNorm(256),nn.GELU())
    def forward(self, b, a):
        bf = self.byte_enc(b); af = self.api_enc(a)
        Q=self.qp(bf).unsqueeze(1); K=self.kp(af).unsqueeze(1); V=self.vp(af).unsqueeze(1)
        ao,_=self.attn(Q,K,V); ao=ao.squeeze(1)
        return self.out(self.norm(bf+self.drop(ao)))


# Minimal HGT (must match training architecture exactly)
class HGTLayer(nn.Module):
    def __init__(self, hidden, heads):
        super().__init__()
        self.heads = heads; self.d = hidden // heads
        self.W_Q = nn.ModuleList([nn.Linear(hidden, self.d) for _ in range(heads)])
        self.W_K = nn.ModuleList([nn.Linear(hidden, self.d) for _ in range(heads)])
        self.W_V = nn.ModuleList([nn.Linear(hidden, self.d) for _ in range(heads)])
        self.out = nn.Linear(hidden, hidden); self.norm = nn.LayerNorm(hidden)
    def forward(self, x, edge_index, *_):
        if edge_index.size(1) == 0: return x
        src, dst = edge_index[0], edge_index[1]
        outs = []
        for h in range(self.heads):
            q=self.W_Q[h](x)[dst]; k=self.W_K[h](x)[src]; v=self.W_V[h](x)[src]
            a=torch.softmax((q*k).sum(-1, keepdim=True)/math.sqrt(self.d), dim=0)
            agg=torch.zeros(x.size(0), self.d, device=x.device)
            agg.scatter_add_(0, dst.unsqueeze(-1).expand_as(v*a), v*a)
            outs.append(agg)
        return self.norm(x + self.out(torch.cat(outs,-1)))


class HGT(nn.Module):
    def __init__(self, in_d, hidden, layers, heads):
        super().__init__()
        self.proj = nn.Linear(in_d, hidden)
        self.layers_= nn.ModuleList([HGTLayer(hidden, heads) for _ in range(layers)])
        self.pool_w = nn.Linear(hidden, 1)
        self.out    = nn.Linear(hidden, hidden*2)
    def get_graph_embedding(self, x, ei, nt, et, batch):
        x=F.gelu(self.proj(x))
        for l in self.layers_: x=l(x,ei,nt,et)
        w=torch.softmax(self.pool_w(x), dim=0)
        B=int(batch.max().item())+1
        pooled=torch.zeros(B,x.size(1),device=x.device)
        pooled.scatter_add_(0,batch.unsqueeze(-1).expand_as(x*w),(x*w))
        return self.out(pooled)


class JointMalwareModel(nn.Module):
    def __init__(self, hgt, resnet, ransomformer, bnn):
        super().__init__()
        self.hgt=hgt; self.resnet=resnet; self.ransomformer=ransomformer; self.bnn=bnn
    def forward(self, x, ei, nt, et, bi, imgs, pb, at, sample=True):
        g=self.hgt.get_graph_embedding(x,ei,nt,et,bi)
        i=self.resnet(imgs)
        r=self.ransomformer(pb,at)
        return self.bnn(torch.cat([g,i,r],-1), sample)
    @torch.no_grad()
    def predict_with_confidence(self, x, ei, nt, et, bi, imgs, pb, at, n=20):
        self.eval()
        probs=[torch.softmax(self.forward(x,ei,nt,et,bi,imgs,pb,at,True),-1) for _ in range(n)]
        probs=torch.stack(probs)
        mp=probs.mean(0); pred=mp.argmax(-1)
        conf=mp[torch.arange(pred.size(0)),pred]
        var=probs[:,torch.arange(pred.size(0)),pred].var(0)
        return pred, conf, var


# ─────────────────────────────────────────────────────────────────────────────
# Feature extraction helpers (inline)
# ─────────────────────────────────────────────────────────────────────────────

def _extract_bytes(path: Path, seq_len=1024, chunk=512, stride=256) -> torch.Tensor:
    try:
        raw = np.frombuffer(path.read_bytes(), dtype=np.uint8).astype(np.float32)
        if len(raw) == 0: return torch.zeros(1, seq_len)
        means = [raw[i:i+chunk].mean() for i in range(0, len(raw), stride)]
        arr   = np.array(means, dtype=np.float32) / 255.0
        if len(arr) >= seq_len: arr = arr[:seq_len]
        else: arr = np.pad(arr, (0, seq_len - len(arr)))
        return torch.from_numpy(arr).unsqueeze(0)
    except Exception: return torch.zeros(1, seq_len)


def _hash_api(name: str, vocab=4096) -> int:
    name = name.lower().split("!")[-1]; h = 5381
    for c in name: h = ((h<<5)+h+ord(c)) & 0xFFFFFFFF
    return (h % (vocab-1)) + 1


_IMAGE_TRANSFORM = None
def _get_transform():
    global _IMAGE_TRANSFORM
    if _IMAGE_TRANSFORM is None and HAS_VISION:
        _IMAGE_TRANSFORM = transforms.Compose([
            transforms.Resize((224,224)), transforms.ToTensor(),
            transforms.Normalize([0.485,0.456,0.406],[0.229,0.224,0.225])
        ])
    return _IMAGE_TRANSFORM


def _file_to_image(path: Path) -> torch.Tensor:
    try:
        raw = np.frombuffer(path.read_bytes(), dtype=np.uint8)
        if len(raw) == 0: return torch.zeros(3,224,224)
        side = max(1, int(math.sqrt(len(raw))))
        raw  = raw[:side*side]
        if len(raw) < side*side:
            raw = np.pad(raw,(0,side*side-len(raw)))
        img  = PILImage.fromarray(raw.reshape(side,side)).convert("RGB")
        t    = _get_transform()
        return t(img) if t else torch.zeros(3,224,224)
    except Exception: return torch.zeros(3,224,224)


def _build_dummy_graph(device, in_dim=320):
    """Build minimal 1-node graph when no pre-extracted graph is available."""
    x = torch.zeros(1, in_dim, device=device)
    ei = torch.zeros(2,0,dtype=torch.long, device=device)
    nt = torch.zeros(1,dtype=torch.long, device=device)
    et = torch.zeros(0,dtype=torch.long, device=device)
    bi = torch.zeros(1,dtype=torch.long, device=device)
    return x, ei, nt, et, bi


def _extract_api_imports(file_path: Path) -> list:
    imports = []
    try:
        import pefile
        pe = pefile.PE(str(file_path), fast_load=True)
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                if entry.dll:
                    dll_name = entry.dll.decode('utf-8', errors='replace')
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8', errors='replace')
                            imports.append(f"{dll_name}!{func_name}")
        pe.close()
    except Exception:
        pass
    return imports


def _extract_api_tokens(api_names: list, max_apis: int = 256, vocab_size: int = 4096) -> torch.Tensor:
    tokens = []
    for n in api_names:
        if n:
            name = n.lower().split("!")[-1]
            h = 5381
            for ch in name:
                h = ((h << 5) + h) + ord(ch)
                h &= 0xFFFFFFFF
            token = (h % (vocab_size - 1)) + 1
            tokens.append(token)
    if not tokens:
        return torch.zeros(max_apis, dtype=torch.long)
    if len(tokens) >= max_apis:
        tokens = tokens[:max_apis]
    else:
        tokens += [0] * (max_apis - len(tokens))
    return torch.tensor(tokens, dtype=torch.long)


def _save_grayscale_image(file_path: Path, output_path: Path, target_size: int = 224) -> bool:
    try:
        if not file_path.exists():
            return False
        with open(file_path, 'rb') as f:
            data = f.read()
        if not data:
            img = PILImage.new('L', (target_size, target_size), 0)
        else:
            raw_bytes = np.frombuffer(data, dtype=np.uint8)
            num_bytes = len(raw_bytes)
            if num_bytes < 10240:       # < 10 KB
                width = 32
            elif num_bytes < 30720:     # 10 KB - 30 KB
                width = 64
            elif num_bytes < 61440:     # 30 KB - 60 KB
                width = 128
            elif num_bytes < 102400:    # 60 KB - 100 KB
                width = 256
            elif num_bytes < 204800:    # 100 KB - 200 KB
                width = 384
            elif num_bytes < 512000:    # 200 KB - 500 KB
                width = 512
            elif num_bytes < 1024000:   # 500 KB - 1000 KB
                width = 768
            else:                       # >= 1000 KB
                width = 1024
            height = math.ceil(num_bytes / width)
            padded_len = width * height
            if padded_len > num_bytes:
                padded_bytes = np.zeros(padded_len, dtype=np.uint8)
                padded_bytes[:num_bytes] = raw_bytes
            else:
                padded_bytes = raw_bytes
            img_array = padded_bytes.reshape((height, width))
            img = PILImage.fromarray(img_array)
            img = img.resize((target_size, target_size), PILImage.Resampling.BILINEAR)
        img.save(output_path, "PNG")
        return True
    except Exception as e:
        print(f"WARNING: Image generation failed: {e}")
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def load_model(ckpt_path: Path, config: dict, device: torch.device) -> JointMalwareModel:
    hidden   = config.get("hidden_dim",  256)
    n_layers = config.get("num_layers",  4)
    n_heads  = config.get("num_heads",   8)
    n_cls    = config.get("num_classes", 2)
    in_dim   = config.get("embedding_dim", 320)
    fused    = config.get("fused_dim",   1152)

    hgt          = HGT(in_dim, hidden, n_layers, n_heads)
    resnet       = ResNetFeatureExtractor()
    ransomformer = RansomFormerEncoder()
    bnn          = BayesianClassifier(fused, n_cls, hidden)
    model        = JointMalwareModel(hgt, resnet, ransomformer, bnn)

    ckpt = torch.load(ckpt_path, map_location=device)
    state = ckpt.get("model_state", ckpt)
    model.load_state_dict(state, strict=False)
    model.to(device).eval()
    return model


def predict(model_path: str, file_path: str, n_samples: int = 20):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    ckpt   = Path(model_path)
    fpath  = Path(file_path)

    if not ckpt.exists():  print(f"ERROR: Model not found: {ckpt}"); sys.exit(1)
    if not fpath.exists(): print(f"ERROR: File not found: {fpath}");  sys.exit(1)

    # Output paths inside the target file's directory (same prediction folder)
    cpg_path  = fpath.with_suffix(".cpg.json")
    png_path  = fpath.with_suffix(".png")
    feat_path = fpath.with_suffix(".feat.pt")

    # Load config if present alongside the model
    cfg_path = ckpt.parent.parent / "model_config.json"
    config   = json.loads(cfg_path.read_text()) if cfg_path.exists() else {}

    print(f"Loading model from {ckpt} …")
    model = load_model(ckpt, config, device)
    in_dim = model.hgt.proj.in_features

    print(f"Extracting features from {fpath.name} …")
    # 1. Byte sequence
    pb = _extract_bytes(fpath).unsqueeze(0).to(device)   # [1, 1, 1024]
    
    # 2. Grayscale binary image (same logic as batch processor)
    print(f"Generating binary grayscale image -> {png_path.name}")
    _save_grayscale_image(fpath, png_path)
    if png_path.exists():
        img = PILImage.open(png_path).convert("RGB")
    else:
        img = PILImage.fromarray(np.zeros((224, 224, 3), dtype="uint8"))
    
    t = _get_transform()
    imgs = t(img).unsqueeze(0).to(device) if t else torch.zeros(1, 3, 224, 224, device=device)
    
    # 3. CPG Graph and API imports
    api_names = []
    has_extracted_graph = False
    
    if HAS_UIR:
        try:
            print(f"Extracting Code Property Graph (CPG) -> {cpg_path.name}")
            config_uir = UIRConfig()
            config_uir.model.embedding_dim = in_dim
            config_uir.tokenization.embedding_dim = in_dim
            processor = FileProcessor(config_uir)
            cpg = processor.process(fpath, use_cache=False)
            if cpg is not None and cpg.num_nodes > 0:
                _ds = CPGDataset.__new__(CPGDataset)
                _ds.embedding_dim = in_dim
                _ds.max_nodes     = config_uir.cpg.max_nodes_per_graph
                data = _ds._cpg_to_data(cpg)
                
                x = data.x.to(device)
                ei = data.edge_index.to(device)
                nt = data.node_types.to(device)
                et = data.edge_types.to(device)
                bi = torch.zeros(x.size(0), dtype=torch.long, device=device)
                
                if cpg.metadata:
                    api_names = list(cpg.metadata.get("imports", []))
                
                # Save CPG JSON file
                cpg.save(cpg_path)
                
                print(f"Extracted actual graph with {x.size(0)} nodes and {ei.size(1)} edges.")
                has_extracted_graph = True
            else:
                print("WARNING: CPG extraction returned empty graph.")
        except Exception as e:
            print(f"WARNING: CPG extraction failed: {e}")
            
    if not has_extracted_graph:
        print("Using dummy graph fallback.")
        x, ei, nt, et, bi = _build_dummy_graph(device, in_dim=in_dim)
        
    if not api_names:
        api_names = _extract_api_imports(fpath)
        
    at = _extract_api_tokens(api_names).unsqueeze(0).to(device) # [1, 256]

    print(f"Running {n_samples} Monte Carlo samples …")
    pred, conf, var = model.predict_with_confidence(
        x, ei, nt, et, bi, imgs, pb, at, n=n_samples
    )

    label_map = {0:"BENIGN", 1:"MALWARE"}
    p = pred[0].item(); c = conf[0].item(); v = var[0].item()

    # Save feature tensors to .feat.pt file
    try:
        print(f"Saving extracted feature tensors -> {feat_path.name}")
        feat = {
            "x":          x.cpu(),
            "edge_index": ei.cpu(),
            "node_types": nt.cpu(),
            "edge_types": et.cpu(),
            "image":      imgs.squeeze(0).cpu(),
            "pe_bytes":   pb.squeeze(0).cpu(),
            "api_tokens": at.squeeze(0).cpu(),
            "label":      p,  # Use predicted class label
            "stem":       fpath.stem,
        }
        torch.save(feat, feat_path)
    except Exception as e:
        print(f"WARNING: Failed to save .feat.pt file: {e}")

    print("\n" + "="*62)
    print("   QUAD-MODAL MALWARE DETECTION  (HGT+ResNet+RansomFormer+BNN)")
    print("="*62)
    print(f"  File:        {fpath.name}")
    print(f"  Prediction:  {label_map.get(p,'UNKNOWN')}")
    print(f"  Confidence:  {c*100:.2f}%")
    print(f"  Uncertainty: {v:.6f}")
    print("="*62 + "\n")
    return p


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="ViGil standalone malware predictor")
    ap.add_argument("--model",   "-m", required=True, help="Path to joint_model.pt")
    ap.add_argument("--file",    "-f", required=True, help="PE/binary file to analyse")
    ap.add_argument("--samples", "-s", type=int, default=20, help="MC samples (default 20)")
    args = ap.parse_args()
    sys.exit(0 if predict(args.model, args.file, args.samples) is not None else 1)
