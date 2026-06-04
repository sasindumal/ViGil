"""
CPG Dataset Module

PyTorch dataset for CPG-based training.
Enhanced with rich feature engineering (320-dim):
  - Function-level: cyclomatic complexity, API call count, BB count, total instructions
  - Block-level: entropy, jump ratio, memory-access ratio, call ratio
  - Malware API fingerprint (68-dim hashed suspicious API names)
  - Global import bag-of-words (68-dim hashed) broadcast to every node
  - PE metadata: architecture, subsystem, timestamp, import/string/export counts
"""

import torch
from torch.utils.data import Dataset
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Set
import json
import logging
import math
import hashlib

from ..cpg.graph import CodePropertyGraph
from ..cpg.schema import NodeType, EdgeType

logger = logging.getLogger(__name__)


# ── Type index maps ───────────────────────────────────────────────────────────
NODE_TYPE_MAP = {nt: i for i, nt in enumerate(NodeType)}
EDGE_TYPE_MAP = {et: i for i, et in enumerate(EdgeType)}

ALL_INST_KEYS = [
    'CALL', 'RETURN', 'CONTROL_STRUCTURE', 'OPERATOR', 'LITERAL', 'IDENTIFIER',
    '<operator>.addition', '<operator>.subtraction', '<operator>.multiplication',
    '<operator>.division', '<operator>.modulo', '<operator>.negation',
    '<operator>.bitAnd', '<operator>.bitOr', '<operator>.bitXor', '<operator>.bitNot',
    '<operator>.leftShift', '<operator>.rightShift', '<operator>.equals',
    '<operator>.notEquals', '<operator>.lessThan', '<operator>.lessEqual',
    '<operator>.greaterThan', '<operator>.greaterEqual', '<operator>.logicalAnd',
    '<operator>.logicalOr', '<operator>.logicalNot', '<operator>.assignment',
    '<operator>.load', '<operator>.store', '<operator>.addressOf',
    '<operator>.dereference', '<operator>.indexAccess', '<operator>.memberAccess',
    '<operator>.cast',
    'IF', 'ELSE', 'WHILE', 'FOR', 'DO', 'SWITCH', 'TRY', 'CATCH', 'FINALLY'
]
INST_KEY_TO_IDX = {key: 100 + i for i, key in enumerate(ALL_INST_KEYS)}

# ── Feature layout (320 dims total) ──────────────────────────────────────────
# [0..10]    Node type one-hot (11 dims)
# [11..13]   in/out/combined degree (log-normalized)
# [14..21]   edge-type specific in-degrees  (8 dims)
# [22..29]   edge-type specific out-degrees (8 dims)
# [30]       is_external flag
# [31]       normalized line number
# [32..99]   Name n-gram multi-hash (68 dims)
# [100..131] Block instruction composition counts (32 dims)
# [132]      Cyclomatic complexity (METHOD)
# [133]      API call count (METHOD)
# [134]      Total instruction count (METHOD)
# [135]      Basic block count (METHOD)
# [136]      Outgoing call count (METHOD/BLOCK)
# [137]      Entropy of instruction distribution (BLOCK)
# [138]      Jump/branch instruction ratio (BLOCK)
# [139]      Memory access ratio (BLOCK)
# [140]      Call ratio (BLOCK)
# [141]      Normalized block size (BLOCK)
# [142..209] Malware API fingerprint (68-dim multi-hash)
# [210..277] Graph-level import bag-of-words (68-dim) — broadcast to all nodes
# [278]      Architecture: x86=1, x64=0.67, arm=0.33, unknown=0
# [279]      Subsystem normalized
# [280]      File-type encoded
# [281]      PE timestamp normalized
# [282]      Import count (log-normalized)
# [283]      String count (log-normalized)
# [284]      Export count (log-normalized)
# [285..319] Reserved (zeros)
EMBEDDING_DIM = 320

# ── Suspicious / malware-indicative Windows API list ─────────────────────────
SUSPICIOUS_APIS: Set[str] = {
    # Process injection & code execution
    "createremotethread", "virtualalloc", "virtualallocex", "virtualprotect",
    "virtualprotectex", "writeprocessmemory", "readprocessmemory",
    "ntcreatethread", "ntcreatethreadex", "rtlcreateuserthread",
    "zwcreatethreadex", "createfiber", "converttofiberex", "queueuserapc",
    "ntqueueapcthread", "setthreadcontext", "getthreadcontext",
    "resumethread", "ntresumethread", "suspendthread",
    # Memory & shellcode
    "heapcreate", "heapalloc", "mapviewoffile", "mapviewoffileex",
    "createfilemapping", "ntmapviewofsection", "ntcreatesection",
    "zwmapviewofsection", "ntallocatevirtualmemory",
    # Registry persistence
    "regsetvalueex", "regcreatekeyex", "regopenkeyex",
    "regdeletekey", "regdeletevalue", "regqueryvalueex",
    # Network / C2
    "internetopenurl", "internetopen", "internetconnect",
    "httpopenrequest", "httpsendrequest", "winhttpsendrequest",
    "winhttpopenrequest", "wsaconnect", "wsasend", "wsarecv",
    "connect", "send", "recv", "gethostbyname",
    "urldownloadtofile", "urldownloadtocachefile", "dnsquery",
    "getadaptersinfo", "getadaptersaddresses",
    # Anti-analysis / evasion
    "isdebuggerpresent", "checkremotedebuggerpresent",
    "ntqueryinformationprocess", "zwqueryinformationprocess",
    "outputdebugstring", "sleep", "sleepex",
    "gettickcount", "queryperformancecounter",
    "findwindow", "enumprocesses",
    # Persistence / launcher
    "createservice", "openservice", "startservice",
    "shellexecute", "shellexecuteex", "createprocess",
    "createprocessasuser", "winexec",
    # File operations
    "deletefile", "movefileex", "copyfileex",
    "setfileattributes",
    # Cryptography
    "cryptacquirecontext", "cryptencrypt", "cryptdecrypt",
    "cryptcreatehash", "bcryptencrypt", "bcryptdecrypt",
    # Token / privilege escalation
    "adjusttokenprivileges", "openprocesstoken", "openthreadtoken",
    "lookupprivilegevalue", "duplicatetokenex",
}


def _deterministic_hash(s: str) -> int:
    """Fast deterministic polynomial hash."""
    h = 0
    for c in s:
        h = (31 * h + ord(c)) & 0xFFFFFFFF
    return h


def _multi_hash_into(feat: torch.Tensor, text: str, start: int, num_buckets: int = 68) -> None:
    """Hash `text` into `num_buckets` buckets at `start` using 3 independent hashes."""
    b = text.encode('utf-8', errors='ignore')
    h1 = int(hashlib.md5(b).hexdigest(), 16) % num_buckets
    h2 = int(hashlib.sha1(b).hexdigest(), 16) % num_buckets
    h3 = _deterministic_hash(text) % num_buckets
    feat[start + h1] = 1.0
    feat[start + h2] = 1.0
    feat[start + h3] = 1.0


def _clean_api_name(name: str) -> str:
    """Strip DLL prefix: 'KERNEL32.dll!VirtualAllocEx' → 'virtualallocex'."""
    if not name:
        return ''
    n = name.lower()
    return n.split('!')[-1] if '!' in n else n


def _is_suspicious_api(name: str) -> bool:
    """Return True if the function name matches a known suspicious API."""
    return _clean_api_name(name) in SUSPICIOUS_APIS


def _compute_graph_global_features(cpg: CodePropertyGraph) -> torch.Tensor:
    """
    Compute 110-dim global feature vector from CPG metadata.

    Layout:
      [0..67]  Import bag-of-words (68-dim hashed)
      [68]     Architecture encoding
      [69]     Subsystem (normalized)
      [70]     File-type encoded
      [71]     PE timestamp (normalized)
      [72]     Import count (log-normalized)
      [73]     String count (log-normalized)
      [74]     Export count (log-normalized)
      [75..109] Reserved zeros
    """
    gfeat = torch.zeros(110)
    meta = cpg.metadata or {}

    # Import n-gram fingerprint (dims 0..67)
    imports = meta.get('imports', [])
    for imp in imports:
        clean = _clean_api_name(imp)
        if clean:
            _multi_hash_into(gfeat, clean, start=0, num_buckets=68)

    # Architecture (dim 68)
    arch = str(meta.get('architecture', '')).lower()
    if 'x86' in arch or arch == 'i386':
        gfeat[68] = 1.0
    elif 'x64' in arch or 'amd64' in arch or arch == 'x86_64':
        gfeat[68] = 2.0 / 3.0
    elif 'arm' in arch:
        gfeat[68] = 1.0 / 3.0

    # Subsystem (dim 69): Windows GUI=2, CUI=3, Native=1
    subsystem = meta.get('subsystem', 0)
    if isinstance(subsystem, (int, float)):
        gfeat[69] = min(float(subsystem) / 10.0, 1.0)

    # File type (dim 70)
    ftype = (cpg.file_type or '').lower()
    ftype_map = {
        'exe': 0.2, 'dll': 0.4, 'sys': 0.6,
        'elf': 0.7, 'macho': 0.8, 'so': 0.75
    }
    gfeat[70] = ftype_map.get(ftype, 0.1)

    # PE timestamp (dim 71)
    ts = meta.get('timestamp', 0)
    if isinstance(ts, (int, float)) and ts > 0:
        gfeat[71] = min(float(ts) / 2e9, 1.0)

    # Count features (dims 72..74)
    gfeat[72] = math.log1p(len(imports)) / 8.0
    gfeat[73] = math.log1p(len(meta.get('strings', []))) / 9.0
    gfeat[74] = math.log1p(len(meta.get('exports', []))) / 6.0

    return gfeat


class CPGData:
    """Single CPG sample with tensor data."""

    def __init__(self):
        self.x: Optional[torch.Tensor] = None          # Node features [N, 320]
        self.edge_index: Optional[torch.Tensor] = None  # [2, E]
        self.node_types: Optional[torch.Tensor] = None  # [N]
        self.edge_types: Optional[torch.Tensor] = None  # [E]
        self.image: Optional[torch.Tensor] = None       # Grayscale image [3, 224, 224]
        self.pe_bytes: Optional[torch.Tensor] = None    # Byte sequence  [1, 1024]
        self.api_tokens: Optional[torch.Tensor] = None  # API token IDs  [max_apis]
        self.y: Optional[torch.Tensor] = None           # [1]
        self.num_nodes: int = 0
        self.num_edges: int = 0
        self.file_path: str = ""

    def to(self, device: torch.device) -> 'CPGData':
        """Move data to device."""
        data = CPGData()
        data.x = self.x.to(device) if self.x is not None else None
        data.edge_index = self.edge_index.to(device) if self.edge_index is not None else None
        data.node_types = self.node_types.to(device) if self.node_types is not None else None
        data.edge_types = self.edge_types.to(device) if self.edge_types is not None else None
        data.image = self.image.to(device) if self.image is not None else None
        data.pe_bytes = self.pe_bytes.to(device) if self.pe_bytes is not None else None
        data.api_tokens = self.api_tokens.to(device) if self.api_tokens is not None else None
        data.y = self.y.to(device) if self.y is not None else None
        data.num_nodes = self.num_nodes
        data.num_edges = self.num_edges
        data.file_path = self.file_path
        return data



class CPGDataset(Dataset):
    """Dataset for CPG graphs with advanced 320-dim feature engineering."""

    def __init__(self,
                 cpg_dir: Path,
                 labels: Optional[Dict[str, int]] = None,
                 embedding_dim: int = EMBEDDING_DIM,
                 max_nodes: int = 10000):
        """
        Initialize CPG dataset.

        Args:
            cpg_dir: Directory containing CPG JSON files
            labels: Dict mapping filename to label (0=benign, 1=malware)
            embedding_dim: Dimension of node features (default 320)
            max_nodes: Maximum nodes per graph
        """
        self.cpg_dir = Path(cpg_dir)
        self.labels = labels or {}
        self.embedding_dim = embedding_dim
        self.max_nodes = max_nodes

        # Find all CPG files
        self.cpg_files = list(self.cpg_dir.rglob("*.json"))
        logger.info(f"Found {len(self.cpg_files)} CPG files")

    def __len__(self) -> int:
        return len(self.cpg_files)

    def __getitem__(self, idx: int) -> CPGData:
        cpg_path = self.cpg_files[idx]

        try:
            cpg = CodePropertyGraph.load(cpg_path)
            data = self._cpg_to_data(cpg)

            # Get label
            source_file = cpg.source_file
            if not source_file:
                source_file = str(cpg_path)
            if source_file in self.labels:
                data.y = torch.tensor([self.labels[source_file]], dtype=torch.long)
            else:
                # Infer from source file path
                source_lower = source_file.lower()
                if any(x in source_lower for x in ['\\benign\\', '/benign/', '\\benigns\\', '/benigns/']):
                    data.y = torch.tensor([0], dtype=torch.long)
                elif any(x in source_lower for x in ['\\malware\\', '/malware/', '\\malwares\\', '/malwares/']):
                    data.y = torch.tensor([1], dtype=torch.long)
                else:
                    data.y = torch.tensor([0], dtype=torch.long)

            # Load corresponding grayscale image
            image_path = cpg_path.with_suffix(".png")
            if not image_path.exists() or image_path == cpg_path:
                # Try finding it in the same folder by replacing .cpg.json with .png
                image_path = Path(str(cpg_path).replace(".cpg.json", ".png"))
                if not image_path.exists() or image_path == cpg_path:
                    # Resolve to a path that does not exist to trigger default fallback
                    image_path = cpg_path.parent / "nonexistent_dummy_image.png"
                
            from PIL import Image
            import torchvision.transforms as transforms
            
            # ImageNet normalization transforms for RGB images
            image_transform = transforms.Compose([
                transforms.ToTensor(),
                transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225])
            ])
            
            if image_path.exists():
                try:
                    img = Image.open(image_path).convert('RGB')
                    data.image = image_transform(img)
                except Exception as img_err:
                    logger.warning(f"Error reading image {image_path}: {img_err}")
                    # Zero fallback
                    data.image = torch.zeros((3, 224, 224))
            else:
                # Zero fallback if image doesn't exist yet
                data.image = torch.zeros((3, 224, 224))

            # ── RansomFormer inputs: PE bytes + API tokens ─────────────────────
            # pe_bytes: sliding-window byte sequence over the original PE file
            # api_tokens: hashed API import names from CPG metadata
            try:
                from ..extraction.pe_feature_extractor import extract_ransomformer_features
                source_pe = Path(cpg.source_file) if cpg.source_file else None
                api_names = list(cpg.metadata.get('imports', [])) if cpg.metadata else []
                if source_pe and source_pe.exists():
                    data.pe_bytes, data.api_tokens = extract_ransomformer_features(
                        source_pe, api_names=api_names
                    )
                else:
                    from ..extraction.pe_feature_extractor import extract_api_tokens, BYTE_SEQ_LEN, MAX_APIS
                    data.pe_bytes = torch.zeros(1, BYTE_SEQ_LEN)
                    data.api_tokens = extract_api_tokens(api_names)
            except Exception as rf_err:
                logger.warning(f"RansomFormer feature extraction failed: {rf_err}")
                data.pe_bytes = torch.zeros(1, 1024)
                data.api_tokens = torch.zeros(256, dtype=torch.long)

            data.file_path = str(cpg_path)
            return data

        except Exception as e:
            logger.error(f"Error loading {cpg_path}: {e}")
            return self._empty_data()


    def _cpg_to_data(self, cpg: CodePropertyGraph) -> CPGData:
        """Convert CPG to tensor data with rich feature engineering."""
        data = CPGData()

        # ── Graph-level global features (broadcast to all nodes later) ────────
        global_feat = _compute_graph_global_features(cpg)

        # ── Identify suspicious external API nodes ────────────────────────────
        suspicious_node_ids: Set[int] = set()
        for n in cpg.nodes.values():
            if n.node_type == NodeType.METHOD and n.is_external and _is_suspicious_api(n.name):
                suspicious_node_ids.add(n.id)

        # ── Per-method: API call count + set of suspicious APIs called ────────
        method_api_call_count: Dict[int, int] = {}
        method_suspicious_apis: Dict[int, Set[str]] = {}

        for edge in cpg.edges:
            if edge.edge_type == EdgeType.CALLS:
                src = cpg.nodes.get(edge.source_id)
                tgt = cpg.nodes.get(edge.target_id)
                if src and tgt and src.node_type == NodeType.METHOD:
                    if tgt.is_external:
                        method_api_call_count[edge.source_id] = (
                            method_api_call_count.get(edge.source_id, 0) + 1
                        )
                    if edge.target_id in suspicious_node_ids:
                        method_suspicious_apis.setdefault(edge.source_id, set()).add(
                            _clean_api_name(tgt.name or '')
                        )

        # ── Determine if graph is already basic-block level ───────────────────
        has_instruction_nodes = any(
            n.node_type not in (NodeType.BLOCK, NodeType.METHOD)
            for n in cpg.nodes.values()
        )

        if has_instruction_nodes:
            bb_nodes = [n for n in cpg.nodes.values()
                        if n.node_type in (NodeType.BLOCK, NodeType.METHOD)]

            # Map each instruction node → its parent BLOCK
            node_to_block: Dict[int, int] = {}
            for n in bb_nodes:
                if n.node_type == NodeType.BLOCK:
                    node_to_block[n.id] = n.id

            for edge in cpg.edges:
                if edge.edge_type == EdgeType.AST and edge.source_id in node_to_block:
                    node_to_block[edge.target_id] = node_to_block[edge.source_id]

            for _ in range(3):
                for edge in cpg.edges:
                    if edge.source_id in node_to_block and edge.target_id not in node_to_block:
                        node_to_block[edge.target_id] = node_to_block[edge.source_id]
                    elif edge.target_id in node_to_block and edge.source_id not in node_to_block:
                        node_to_block[edge.source_id] = node_to_block[edge.target_id]

            # Reconstruct instruction counts per block
            block_inst_counts: Dict[int, Dict[str, int]] = {}
            for node in cpg.nodes.values():
                if node.node_type not in (NodeType.BLOCK, NodeType.METHOD):
                    parent = node_to_block.get(node.id)
                    if parent is not None:
                        bc = block_inst_counts.setdefault(parent, {})
                        key = node.node_type.value
                        if node.operator_type:
                            key = node.operator_type.value
                        elif node.control_type:
                            key = node.control_type.value
                        bc[key] = bc.get(key, 0) + 1

            for n in bb_nodes:
                if n.node_type == NodeType.BLOCK:
                    n.attributes['inst_counts'] = block_inst_counts.get(n.id, {})

            # Reconstruct edges at basic-block level
            new_edges: List[Tuple] = []
            seen_edges: Set[Tuple] = set()

            for edge in cpg.edges:
                src_id, tgt_id, etype = edge.source_id, edge.target_id, edge.edge_type

                if etype == EdgeType.CFG:
                    sb = node_to_block.get(src_id)
                    tb = node_to_block.get(tgt_id)
                    if sb and tb and sb != tb:
                        k = (sb, tb, EdgeType.CFG.value)
                        if k not in seen_edges:
                            seen_edges.add(k)
                            new_edges.append((sb, tb, EdgeType.CFG))

                elif etype == EdgeType.CALLS:
                    sn = cpg.nodes.get(src_id)
                    tn = cpg.nodes.get(tgt_id)
                    if sn and tn:
                        if sn.node_type == NodeType.METHOD and tn.node_type == NodeType.METHOD:
                            k = (src_id, tgt_id, EdgeType.CALLS.value)
                            if k not in seen_edges:
                                seen_edges.add(k)
                                new_edges.append((src_id, tgt_id, EdgeType.CALLS))
                        else:
                            sb = node_to_block.get(src_id)
                            if sb and tn.node_type == NodeType.METHOD:
                                k = (sb, tgt_id, EdgeType.CALLS.value)
                                if k not in seen_edges:
                                    seen_edges.add(k)
                                    new_edges.append((sb, tgt_id, EdgeType.CALLS))

                elif etype == EdgeType.DATA_FLOW:
                    sb = node_to_block.get(src_id)
                    tb = node_to_block.get(tgt_id)
                    if sb and tb and sb != tb:
                        k = (sb, tb, EdgeType.DATA_FLOW.value)
                        if k not in seen_edges:
                            seen_edges.add(k)
                            new_edges.append((sb, tb, EdgeType.DATA_FLOW))

            # METHOD → BLOCK containment edges
            for edge in cpg.edges:
                if edge.edge_type == EdgeType.AST:
                    sn = cpg.nodes.get(edge.source_id)
                    tn = cpg.nodes.get(edge.target_id)
                    if sn and tn and sn.node_type == NodeType.METHOD and tn.node_type == NodeType.BLOCK:
                        k = (edge.source_id, edge.target_id, EdgeType.CFG.value)
                        if k not in seen_edges:
                            seen_edges.add(k)
                            new_edges.append((edge.source_id, edge.target_id, EdgeType.CFG))

            nodes = bb_nodes

        else:
            nodes = list(cpg.nodes.values())
            new_edges = [
                (e.source_id, e.target_id, e.edge_type)
                for e in cpg.edges
                if e.edge_type in (EdgeType.CFG, EdgeType.CALLS, EdgeType.DATA_FLOW)
            ]

        # ── Max-nodes sampling ────────────────────────────────────────────────
        if len(nodes) > self.max_nodes:
            start_ids = [n.id for n in nodes if n.node_type == NodeType.METHOD]
            if not start_ids:
                start_ids = [nodes[0].id]
            adj: Dict[int, List[int]] = {}
            for src, tgt, _ in new_edges:
                adj.setdefault(src, []).append(tgt)
                adj.setdefault(tgt, []).append(src)
            visited: Set[int] = set(start_ids)
            queue = list(start_ids)
            while queue and len(visited) < self.max_nodes:
                curr = queue.pop(0)
                for nb in adj.get(curr, []):
                    if nb not in visited:
                        visited.add(nb)
                        queue.append(nb)
                        if len(visited) >= self.max_nodes:
                            break
            
            # If we still haven't reached max_nodes, add more
            if len(visited) < self.max_nodes:
                for n in nodes:
                    if n.id not in visited:
                        visited.add(n.id)
                        if len(visited) >= self.max_nodes:
                            break
            nodes = [n for n in nodes if n.id in visited]
            new_edges = [(s, t, e) for s, t, e in new_edges if s in visited and t in visited]

        if not nodes:
            return self._empty_data()

        # ── Degree computation ────────────────────────────────────────────────
        in_degrees: Dict[int, int] = {}
        out_degrees: Dict[int, int] = {}
        edge_in_degrees: Dict[Tuple[int, int], int] = {}
        edge_out_degrees: Dict[Tuple[int, int], int] = {}
        node_call_out: Dict[int, int] = {}  # CALLS outgoing count per node

        for src, tgt, etype in new_edges:
            et_idx = EDGE_TYPE_MAP.get(etype, 0)
            out_degrees[src] = out_degrees.get(src, 0) + 1
            in_degrees[tgt] = in_degrees.get(tgt, 0) + 1
            edge_out_degrees[(src, et_idx)] = edge_out_degrees.get((src, et_idx), 0) + 1
            edge_in_degrees[(tgt, et_idx)] = edge_in_degrees.get((tgt, et_idx), 0) + 1
            if etype == EdgeType.CALLS:
                node_call_out[src] = node_call_out.get(src, 0) + 1

        # ── Per-method BB count & total instructions ──────────────────────────
        method_bb_count: Dict[int, int] = {}
        method_total_insts: Dict[int, int] = {}
        for src, tgt, etype in new_edges:
            if etype == EdgeType.CFG:
                sn = cpg.nodes.get(src)
                tn = cpg.nodes.get(tgt)
                if sn and tn and sn.node_type == NodeType.METHOD and tn.node_type == NodeType.BLOCK:
                    method_bb_count[src] = method_bb_count.get(src, 0) + 1
                    bb_insts = tn.attributes.get('num_instructions', 0)
                    method_total_insts[src] = method_total_insts.get(src, 0) + bb_insts

        # ── Cyclomatic complexity per METHOD ──────────────────────────────────
        method_cyclomatic: Dict[int, float] = {}
        for nid, bb_cnt in method_bb_count.items():
            edges_out = out_degrees.get(nid, 0)
            method_cyclomatic[nid] = float(max(edges_out - bb_cnt + 2, 1))

        # ── Build node features ───────────────────────────────────────────────
        data.num_nodes = len(nodes)
        node_id_map = {n.id: i for i, n in enumerate(nodes)}
        valid_ids = set(node_id_map.keys())

        total_nodes = len(nodes)
        total_edges = len(new_edges)

        features: List[torch.Tensor] = []
        node_type_ids: List[int] = []

        for node in nodes:
            n_in = in_degrees.get(node.id, 0)
            n_out = out_degrees.get(node.id, 0)
            etype_in = {et: edge_in_degrees.get((node.id, et), 0) for et in range(8)}
            etype_out = {et: edge_out_degrees.get((node.id, et), 0) for et in range(8)}

            feat = self._node_to_features(
                node=node,
                in_deg=n_in,
                out_deg=n_out,
                etype_in_deg=etype_in,
                etype_out_deg=etype_out,
                total_nodes=total_nodes,
                total_edges=total_edges,
                global_feat=global_feat,
                call_out=node_call_out.get(node.id, 0),
                api_call_count=method_api_call_count.get(node.id, 0),
                suspicious_apis=method_suspicious_apis.get(node.id, set()),
                bb_count=method_bb_count.get(node.id, 0),
                total_insts=method_total_insts.get(node.id, 0),
                cyclomatic=method_cyclomatic.get(node.id, 0.0),
            )
            features.append(feat)
            node_type_ids.append(NODE_TYPE_MAP.get(node.node_type, 0))

        data.x = torch.stack(features)
        data.node_types = torch.tensor(node_type_ids, dtype=torch.long)

        # ── Build edge tensors ────────────────────────────────────────────────
        sources: List[int] = []
        targets: List[int] = []
        edge_type_list: List[int] = []

        for src, tgt, etype in new_edges:
            if src in valid_ids and tgt in valid_ids:
                sources.append(node_id_map[src])
                targets.append(node_id_map[tgt])
                edge_type_list.append(EDGE_TYPE_MAP.get(etype, 0))

        if sources:
            data.edge_index = torch.tensor([sources, targets], dtype=torch.long)
            data.edge_types = torch.tensor(edge_type_list, dtype=torch.long)
        else:
            data.edge_index = torch.zeros((2, 0), dtype=torch.long)
            data.edge_types = torch.zeros(0, dtype=torch.long)

        data.num_edges = len(sources)
        return data

    def _node_to_features(
        self,
        node,
        in_deg: int = 0,
        out_deg: int = 0,
        etype_in_deg: Optional[Dict[int, int]] = None,
        etype_out_deg: Optional[Dict[int, int]] = None,
        total_nodes: int = 1,
        total_edges: int = 0,
        global_feat: Optional[torch.Tensor] = None,
        call_out: int = 0,
        api_call_count: int = 0,
        suspicious_apis: Optional[Set[str]] = None,
        bb_count: int = 0,
        total_insts: int = 0,
        cyclomatic: float = 0.0,
    ) -> torch.Tensor:
        """
        Convert node to 320-dim feature vector.

        Dimensions:
          0-10   : Node type one-hot
          11-13  : Degree features (log-norm)
          14-21  : Edge-type in-degrees
          22-29  : Edge-type out-degrees
          30     : is_external
          31     : line number (norm)
          32-99  : Name n-gram multi-hash (68-dim)
          100-131: Block instruction composition (32-dim)
          132-141: Function/block-level metrics
          142-209: Malware API fingerprint (68-dim)
          210-277: Global import bag-of-words (68-dim)
          278-284: PE metadata
          285-319: Reserved
        """
        feat = torch.zeros(self.embedding_dim)

        # 1. Node type one-hot (dims 0..10)
        type_id = NODE_TYPE_MAP.get(node.node_type, 0)
        if 0 <= type_id < min(11, self.embedding_dim):
            feat[type_id] = 1.0

        # 2. Degree features (dims 11..13)
        if self.embedding_dim >= 14:
            feat[11] = math.log1p(in_deg) / 5.0
            feat[12] = math.log1p(out_deg) / 5.0
            feat[13] = math.log1p(in_deg + out_deg) / 5.0

        # Edge-type in-degrees (dims 14..21)
        if etype_in_deg:
            for et_idx, count in etype_in_deg.items():
                if 0 <= et_idx < 8:
                    idx = 14 + et_idx
                    if idx < self.embedding_dim:
                        feat[idx] = math.log1p(count) / 5.0

        # Edge-type out-degrees (dims 22..29)
        if etype_out_deg:
            for et_idx, count in etype_out_deg.items():
                if 0 <= et_idx < 8:
                    idx = 22 + et_idx
                    if idx < self.embedding_dim:
                        feat[idx] = math.log1p(count) / 5.0

        # 3. Node attributes (dims 30..31)
        if node.is_external and self.embedding_dim >= 31:
            feat[30] = 1.0
        if node.line_number and node.line_number > 0 and self.embedding_dim >= 32:
            feat[31] = min(node.line_number / 1000.0, 1.0)

        # 4. Name n-gram multi-hash (dims 32..99)
        if node.name and self.embedding_dim >= 100:
            name = _clean_api_name(node.name)
            ngrams = [name[i:i+3] for i in range(len(name) - 2)]
            if not ngrams:
                ngrams = [name]
            for ng in ngrams:
                _multi_hash_into(feat, ng, start=32, num_buckets=68)

        # 5. Block instruction composition counts (dims 100..131)
        if node.node_type == NodeType.BLOCK:
            inst_counts = node.attributes.get('inst_counts', {})
            for k, count in inst_counts.items():
                if k in INST_KEY_TO_IDX:
                    idx = INST_KEY_TO_IDX[k]
                    if idx < self.embedding_dim:
                        feat[idx] = min(count / 10.0, 1.0)

        # 6. Function-level metrics (dims 132..141)
        if node.node_type == NodeType.METHOD:
            if self.embedding_dim >= 133:
                feat[132] = min(cyclomatic / 30.0, 1.0)              # cyclomatic complexity
            if self.embedding_dim >= 134:
                feat[133] = math.log1p(api_call_count) / 5.0         # API call count
            if self.embedding_dim >= 135:
                feat[134] = math.log1p(total_insts) / 8.0            # total instructions
            if self.embedding_dim >= 136:
                feat[135] = math.log1p(bb_count) / 5.0               # basic block count
            if self.embedding_dim >= 137:
                feat[136] = math.log1p(call_out) / 5.0               # outgoing call edges

        elif node.node_type == NodeType.BLOCK:
            inst_counts = node.attributes.get('inst_counts', {})
            total_inst = max(sum(inst_counts.values()), 1)
            num_instructions = node.attributes.get('num_instructions', total_inst)

            # Entropy of instruction type distribution
            entropy = 0.0
            for cnt in inst_counts.values():
                if cnt > 0:
                    p = cnt / total_inst
                    entropy -= p * math.log2(p)
            if self.embedding_dim >= 138:
                feat[137] = min(entropy / 4.0, 1.0)                  # instruction entropy

            # Jump/branch ratio
            jump_count = (inst_counts.get('BRANCH', 0) +
                          inst_counts.get('CBRANCH', 0) +
                          inst_counts.get('RETURN', 0))
            if self.embedding_dim >= 139:
                feat[138] = jump_count / total_inst                   # jump ratio

            # Memory access ratio
            mem_count = inst_counts.get('LOAD', 0) + inst_counts.get('STORE', 0)
            if self.embedding_dim >= 140:
                feat[139] = mem_count / total_inst                    # memory access ratio

            # Call ratio
            if self.embedding_dim >= 141:
                feat[140] = inst_counts.get('CALL', 0) / total_inst  # call ratio

            # Block size
            if self.embedding_dim >= 142:
                feat[141] = min(num_instructions / 50.0, 1.0)        # block size (norm)

            # Outgoing call count
            if self.embedding_dim >= 137:
                feat[136] = math.log1p(call_out) / 5.0

        # 7. Malware API fingerprint (dims 142..209)
        # For METHOD nodes: hash all suspicious APIs this method calls
        if self.embedding_dim >= 210:
            if node.node_type == NodeType.METHOD and suspicious_apis:
                for api_name in suspicious_apis:
                    if api_name:
                        _multi_hash_into(feat, api_name, start=142, num_buckets=68)
            # For external METHOD nodes that ARE suspicious: fingerprint themselves
            if node.node_type == NodeType.METHOD and node.is_external and _is_suspicious_api(node.name):
                clean = _clean_api_name(node.name or '')
                if clean:
                    _multi_hash_into(feat, clean, start=142, num_buckets=68)

        # 8. Global import bag-of-words (dims 210..277) — broadcast to every node
        if global_feat is not None and self.embedding_dim >= 278:
            feat[210:278] = global_feat[0:68]

        # 9. PE metadata features (dims 278..284)
        if global_feat is not None and self.embedding_dim >= 285:
            feat[278:285] = global_feat[68:75]

        return feat

    def _empty_data(self) -> CPGData:
        """Return empty data for failed loads."""
        data = CPGData()
        data.x = torch.zeros((1, self.embedding_dim))
        data.edge_index = torch.zeros((2, 0), dtype=torch.long)
        data.node_types = torch.zeros(1, dtype=torch.long)
        data.edge_types = torch.zeros(0, dtype=torch.long)
        data.image = torch.zeros((3, 224, 224))
        data.pe_bytes = torch.zeros(1, 1024)
        data.api_tokens = torch.zeros(256, dtype=torch.long)
        data.y = torch.tensor([0], dtype=torch.long)
        data.num_nodes = 1
        data.num_edges = 0
        return data


def collate_cpg_batch(batch: List[CPGData]) -> Tuple[CPGData, torch.Tensor]:
    """Collate a batch of CPG data into a single graph with batch indices."""
    xs = []
    edge_indices = []
    node_types = []
    edge_types = []
    ys = []
    batches = []
    node_offset = 0

    images = []
    pe_bytes_list = []
    api_tokens_list = []

    for i, data in enumerate(batch):
        xs.append(data.x)
        node_types.append(data.node_types)

        if data.edge_index is not None and data.edge_index.size(1) > 0:
            edge_indices.append(data.edge_index + node_offset)
            edge_types.append(data.edge_types)

        ys.append(data.y)
        batches.append(torch.full((data.num_nodes,), i, dtype=torch.long))
        node_offset += data.num_nodes

        # Image fallback
        if data.image is not None:
            images.append(data.image)
        else:
            images.append(torch.zeros(3, 224, 224))

        # PE byte sequence fallback
        if data.pe_bytes is not None:
            pe_bytes_list.append(data.pe_bytes)
        else:
            pe_bytes_list.append(torch.zeros(1, 1024))

        # API token fallback
        if data.api_tokens is not None:
            api_tokens_list.append(data.api_tokens)
        else:
            api_tokens_list.append(torch.zeros(256, dtype=torch.long))

    combined = CPGData()
    combined.x = torch.cat(xs, dim=0)
    combined.node_types = torch.cat(node_types, dim=0)
    combined.y = torch.cat(ys, dim=0)
    combined.image = torch.stack(images, dim=0)        # [B, 3, 224, 224]
    combined.pe_bytes = torch.stack(pe_bytes_list, dim=0)    # [B, 1, 1024]
    combined.api_tokens = torch.stack(api_tokens_list, dim=0)  # [B, max_apis]

    if edge_indices:
        combined.edge_index = torch.cat(edge_indices, dim=1)
        combined.edge_types = torch.cat(edge_types, dim=0)
    else:
        combined.edge_index = torch.zeros((2, 0), dtype=torch.long)
        combined.edge_types = torch.zeros(0, dtype=torch.long)

    batch_tensor = torch.cat(batches, dim=0)
    return combined, batch_tensor


# ─────────────────────────────────────────────────────────────────────────────
# PreExtractedDataset — loads .feat.pt files (for Kaggle training)
# ─────────────────────────────────────────────────────────────────────────────

class PreExtractedDataset(Dataset):
    """
    Dataset that loads pre-extracted .feat.pt files saved by the batch processor.

    Each .feat.pt contains all 4 modality tensors so Kaggle training never
    needs the original PE binaries or CPG extraction code.

    Expected file layout:
        root/
          benigns/   *.feat.pt   (label=0)
          malwares/  *.feat.pt   (label=1)

    Args:
        feat_dir: Root directory containing the .feat.pt files.
    """

    def __init__(self, feat_dir: Path):
        self.feat_dir = Path(feat_dir)
        self.feat_files: List[Path] = sorted(self.feat_dir.rglob("*.feat.pt"))
        logger.info(
            f"PreExtractedDataset: found {len(self.feat_files)} .feat.pt files "
            f"in {feat_dir}"
        )

    def __len__(self) -> int:
        return len(self.feat_files)

    def __getitem__(self, idx: int) -> CPGData:
        path = self.feat_files[idx]
        try:
            feat = torch.load(path, map_location="cpu", weights_only=True)
        except TypeError:
            feat = torch.load(path, map_location="cpu")

        data = CPGData()
        data.x          = feat.get("x",          torch.zeros(1, 320))
        data.edge_index = feat.get("edge_index",  torch.zeros(2, 0, dtype=torch.long))
        data.node_types = feat.get("node_types",  torch.zeros(data.x.size(0), dtype=torch.long))
        data.edge_types = feat.get("edge_types",  torch.zeros(0, dtype=torch.long))
        data.image      = feat.get("image",       torch.zeros(3, 224, 224))
        data.pe_bytes   = feat.get("pe_bytes",    torch.zeros(1, 1024))
        data.api_tokens = feat.get("api_tokens",  torch.zeros(256, dtype=torch.long))
        data.num_nodes  = data.x.size(0)
        data.num_edges  = data.edge_index.size(1)
        data.file_path  = str(path)

        label  = feat.get("label", 0)
        data.y = torch.tensor([int(label)], dtype=torch.long)
        return data
