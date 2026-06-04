"""
ResNet-50 Feature Extractor for Grayscale Malware Images

Replaces LeViT-128S + LoRA with a torchvision ResNet-50 backbone.
No HuggingFace dependency — works offline on Kaggle without internet.

Architecture:
  ResNet-50 (pretrained on ImageNet)
  → Freeze layers 1–3 (conv1, bn1, layer1, layer2, layer3)
  → Fine-tune layer4  (~8.5M params)
  → Replace avgpool + fc with AdaptiveAvgPool + Linear(2048, 384)
  → Output: [B, 384]

Output dimension matches the old LeViT-128S extractor (384-dim)
so the fused BNN input stays at 512 + 384 + 256 = 1152.
"""

import torch
import torch.nn as nn
import logging

logger = logging.getLogger(__name__)


class ResNetFeatureExtractor(nn.Module):
    """
    ResNet-50 image feature extractor.

    Input:  [B, 3, 224, 224]  (ImageNet-normalized RGB)
    Output: [B, 384]

    Training strategy:
      - layers conv1, bn1, layer1, layer2, layer3 → frozen
      - layer4 → trainable (fine-tuned)
      - projection head Linear(2048→384) → trainable
    """

    OUT_DIM: int = 384

    def __init__(self, pretrained: bool = True, freeze_backbone: bool = True):
        super().__init__()

        try:
            import torchvision.models as models
            # Use updated weights API if available (torchvision >= 0.13)
            try:
                from torchvision.models import ResNet50_Weights
                backbone = models.resnet50(
                    weights=ResNet50_Weights.IMAGENET1K_V2 if pretrained else None
                )
            except ImportError:
                backbone = models.resnet50(pretrained=pretrained)

            logger.info(f"Loaded ResNet-50 (pretrained={pretrained})")
        except Exception as e:
            logger.warning(f"Could not load pretrained ResNet-50: {e}. Using random init.")
            import torchvision.models as models
            backbone = models.resnet50(pretrained=False)

        # ── Strip the final FC and avgpool ────────────────────────────────────
        self.conv1  = backbone.conv1
        self.bn1    = backbone.bn1
        self.relu   = backbone.relu
        self.maxpool = backbone.maxpool
        self.layer1 = backbone.layer1
        self.layer2 = backbone.layer2
        self.layer3 = backbone.layer3
        self.layer4 = backbone.layer4

        self.avgpool = nn.AdaptiveAvgPool2d((1, 1))
        self.dropout = nn.Dropout(0.2)
        self.projection = nn.Sequential(
            nn.Linear(2048, self.OUT_DIM),
            nn.LayerNorm(self.OUT_DIM),
            nn.GELU(),
        )

        if freeze_backbone:
            self._freeze_early_layers()

    def _freeze_early_layers(self):
        """Freeze everything except layer4 and the projection head."""
        frozen_modules = [
            self.conv1, self.bn1,
            self.layer1, self.layer2, self.layer3,
        ]
        for mod in frozen_modules:
            for param in mod.parameters():
                param.requires_grad = False

        trainable = sum(
            p.numel() for p in self.parameters() if p.requires_grad
        )
        total = sum(p.numel() for p in self.parameters())
        logger.info(
            f"ResNet-50: {trainable:,} / {total:,} params trainable "
            f"({100 * trainable / total:.1f}%)"
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Args:
            x: [B, 3, 224, 224]  ImageNet-normalized RGB image
        Returns:
            [B, 384]
        """
        x = self.conv1(x)
        x = self.bn1(x)
        x = self.relu(x)
        x = self.maxpool(x)

        x = self.layer1(x)
        x = self.layer2(x)
        x = self.layer3(x)
        x = self.layer4(x)           # [B, 2048, 7, 7]

        x = self.avgpool(x)          # [B, 2048, 1, 1]
        x = x.flatten(1)             # [B, 2048]
        x = self.dropout(x)
        x = self.projection(x)       # [B, 384]
        return x
