"""Coleta de artefatos a partir de imagens de disco forenses (E01/RAW).

A imagem é tratada como fonte somente-leitura; cada artefato extraído é
hasheado e registrado no manifesto (ISO/IEC 27037).
"""

from __future__ import annotations

from pathlib import Path

from forensic_triage.collectors.base_collector import BaseCollector


class ImageCollector(BaseCollector):
    """Extrai artefatos de uma imagem de disco forense."""

    def __init__(self, image_path: Path, **kwargs) -> None:
        super().__init__(**kwargs)
        self.image_path = image_path
        if not image_path.is_file():
            raise FileNotFoundError(f"Imagem não encontrada: {image_path}")

    def collect(self) -> list:
        # Registra a imagem em si como evidência de origem.
        artifact = self._preserve(
            self.image_path, f"image/{self.image_path.name}"
        )
        self.audit.log_action(
            "image_mount",
            {"image": self.image_path.name, "sha256": artifact.sha256[:16]},
        )
        return [artifact]