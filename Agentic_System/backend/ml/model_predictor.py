"""
ViGil — ML Model Predictor
==========================

Wraps the existing ViGil quad-modal PyTorch model for backend API use.
Loads the checkpoint (singleton) and runs Monte Carlo dropout inference.
"""

from __future__ import annotations

import sys
import asyncio
import logging
from pathlib import Path
from typing import Any, Optional

import torch

# Add the parent ViGil directory to sys.path so we can import 'predict' and 'uir'
# ViGil_ROOT is the parent of Agentic_System/
PARENT_DIR = str(Path(__file__).resolve().parent.parent.parent.parent)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

# Import get_config from backend
from backend.config import get_config

logger = logging.getLogger("vigil.model_predictor")


class ModelPredictor:
    """Wrapper class for loading and running the ViGil neural network model."""

    _instance: Optional[ModelPredictor] = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self.device = self._detect_device()
        self.model_loaded = False
        self.model_config = {}

    def _detect_device(self) -> torch.device:
        """Detect the optimal PyTorch device."""
        if torch.cuda.is_available():
            dev = torch.device("cuda")
        elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
            dev = torch.device("mps")
        else:
            dev = torch.device("cpu")
        logger.info("Auto-detected PyTorch device: %s", dev)
        return dev

    def is_loaded(self) -> bool:
        """Return whether the model is successfully loaded."""
        return self.model_loaded

    async def load_model(self) -> bool:
        """Load the model checkpoint in a separate thread.

        Returns
        -------
        bool
            True if loading succeeded, False otherwise.
        """
        if self.model_loaded:
            return True

        cfg = get_config()
        checkpoint_path = cfg.storage.model_checkpoint
        config_path = cfg.storage.model_config_path

        if not checkpoint_path.exists():
            logger.warning(
                "Model checkpoint not found at %s. Model-based classification will be unavailable.",
                checkpoint_path
            )
            return False

        try:
            # We run the actual load in an executor to avoid blocking the asyncio event loop
            def perform_load():
                # Import predict inside the thread to avoid circular dependencies or import locks
                import predict
                model_cfg = predict._load_model_cfg(checkpoint_path)
                model = predict._build_model(model_cfg, self.device)
                model = predict._load_checkpoint(model, checkpoint_path, self.device)
                return model_cfg, model

            logger.info("Loading joint model checkpoint in background...")
            model_cfg, _ = await asyncio.get_event_loop().run_in_executor(None, perform_load)
            self.model_config = model_cfg
            self.model_loaded = True
            logger.info("Joint model loaded successfully.")
            return True

        except Exception as exc:
            logger.exception("Error loading ViGil model: %s", exc)
            return False

    async def predict(self, file_path: Path, num_samples: Optional[int] = None) -> dict[str, Any]:
        """Run quad-modal BNN inference on the specified file.

        Parameters
        ----------
        file_path:
            The path to the file to classify.
        num_samples:
            Number of Monte Carlo dropout samples to run (defaults to config value).

        Returns
        -------
        dict
            Contains prediction keys: file, prediction, label, confidence, variance.
        """
        cfg = get_config()
        if num_samples is None:
            num_samples = cfg.analysis.mc_dropout_samples

        checkpoint_path = cfg.storage.model_checkpoint

        if not self.model_loaded:
            loaded = await self.load_model()
            if not loaded:
                raise RuntimeError("Cannot run inference: ViGil model could not be loaded.")

        try:
            # Run inference in a thread pool since feature extraction and torch operations are CPU/GPU heavy
            def perform_predict():
                import predict
                return predict.predict(
                    file_path=file_path,
                    checkpoint_path=checkpoint_path,
                    num_samples=num_samples,
                    verbose=False,
                    device_str=str(self.device)
                )

            logger.info("Running ML inference on %s (T=%d samples)", file_path.name, num_samples)
            res = await asyncio.get_event_loop().run_in_executor(None, perform_predict)
            return res

        except Exception as exc:
            logger.exception("ML inference failed for %s: %s", file_path.name, exc)
            return {
                "file": str(file_path),
                "prediction": -1,
                "label": "ERROR",
                "confidence": 0.0,
                "variance": 0.0,
                "error": str(exc)
            }

    def get_model_info(self) -> dict[str, Any]:
        """Return metadata about the loaded model architecture."""
        return {
            "loaded": self.model_loaded,
            "device": str(self.device),
            "config": self.model_config,
        }
