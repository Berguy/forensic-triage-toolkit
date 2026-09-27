"""Funções de hashing forense em blocos (chunks) — ISO/IEC 27037.

Processa arquivos grandes sem carregá-los na memória, preservando
integridade e permitindo verificação posterior.
"""
from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path

CHUNK_SIZE = 1024 * 1024  # 1 MiB

HashFunc = Callable[[], "hashlib._Hash"]

_ALGORITHMS: dict[str, HashFunc] = {
    "sha256": hashlib.sha256,
    "sha3_256": hashlib.sha3_256,
    "blake2b": hashlib.blake2b,
}


def hash_file(path: Path, algorithm: str = "sha256", chunk_size: int = CHUNK_SIZE) -> str:
    """Calcula o hash de um arquivo em blocos, sem carregá-lo inteiro na memória."""
    if algorithm not in _ALGORITHMS:
        raise ValueError(f"Algoritmo não suportado: {algorithm}. Use {sorted(_ALGORITHMS)}")

    hasher = _ALGORITHMS[algorithm]()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()


def hash_bytes(data: bytes, algorithm: str = "sha256") -> str:
    """Calcula o hash de um bloco de bytes."""
    if algorithm not in _ALGORITHMS:
        raise ValueError(f"Algoritmo não suportado: {algorithm}")
    return _ALGORITHMS[algorithm](data).hexdigest()