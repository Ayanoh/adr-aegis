"""Vector similarity matching engine for threat detection.

Uses ChromaDB for vector storage and sentence-transformers for embedding generation.
Falls back gracefully if vector dependencies are not installed.
"""

import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

from vinci_adr.core.schema import (
    ActionDecision,
    ThreatMatch,
    ThreatSeverity,
    TierSource,
    Verdict,
)

logger = structlog.get_logger()

# Embedding model configuration
EMBEDDING_MODEL = "all-MiniLM-L6-v2"
EMBEDDING_DIM = 384

# Default similarity thresholds (lowered for better detection)
DEFAULT_CRITICAL_THRESHOLD = 0.80  # Very high similarity = definitely malicious
DEFAULT_HIGH_THRESHOLD = 0.65  # High similarity = likely malicious
DEFAULT_MEDIUM_THRESHOLD = 0.50  # Medium similarity = suspicious

# Collection names
COLLECTION_ATTACKS = "known_attacks"


@dataclass
class VectorMatch:
    """A match found in the vector database.

    Attributes:
        id: Unique identifier of the matched document.
        content: Original text content of the matched document.
        similarity: Cosine similarity score (0.0-1.0).
        metadata: Additional metadata (category, severity, etc.).
        distance: Raw distance from the query vector.
    """

    id: str
    content: str
    similarity: float
    metadata: dict[str, Any] = field(default_factory=dict)
    distance: float = 0.0


class VectorMatcher:
    """Vector similarity matching for threat detection.

    Uses ChromaDB for storage and sentence-transformers for embeddings.
    Falls back gracefully if dependencies are not available.

    Attributes:
        db_path: Path to ChromaDB persistence directory.
        critical_threshold: Similarity threshold for critical matches.
        high_threshold: Similarity threshold for high severity matches.
        medium_threshold: Similarity threshold for medium severity matches.
    """

    def __init__(
        self,
        db_path: Path | None = None,
        critical_threshold: float = DEFAULT_CRITICAL_THRESHOLD,
        high_threshold: float = DEFAULT_HIGH_THRESHOLD,
        medium_threshold: float = DEFAULT_MEDIUM_THRESHOLD,
        auto_load: bool = True,
    ) -> None:
        """Initialize the vector matcher.

        Args:
            db_path: Path to persist ChromaDB. If None, uses in-memory storage.
            critical_threshold: Similarity threshold for critical severity.
            high_threshold: Similarity threshold for high severity.
            medium_threshold: Similarity threshold for medium severity.
            auto_load: Whether to automatically initialize on creation.
        """
        self.db_path = db_path
        self.critical_threshold = critical_threshold
        self.high_threshold = high_threshold
        self.medium_threshold = medium_threshold

        self._client: Any = None
        self._collection: Any = None
        self._embedding_model: Any = None
        self._initialized: bool = False

        if auto_load:
            self._initialize()

    def _initialize(self) -> None:
        """Initialize ChromaDB and embedding model."""
        try:
            import chromadb
            from chromadb.utils import embedding_functions
            from sentence_transformers import SentenceTransformer
        except ImportError as e:
            logger.warning(
                "Vector matching dependencies not available",
                error=str(e),
            )
            return

        try:
            # Load embedding model FIRST (sentence-transformers)
            self._embedding_model = SentenceTransformer(EMBEDDING_MODEL)

            # Use sentence-transformers embedding function from ChromaDB
            self._embedding_fn = (
                embedding_functions.SentenceTransformerEmbeddingFunction(
                    model_name=EMBEDDING_MODEL
                )
            )

            # Initialize ChromaDB
            if self.db_path:
                self._client = chromadb.PersistentClient(path=str(self.db_path))
            else:
                self._client = chromadb.Client()

            # Get or create collection with our custom embedding function
            self._collection = self._client.get_or_create_collection(
                name=COLLECTION_ATTACKS,
                metadata={"hnsw:space": "cosine"},
                embedding_function=self._embedding_fn,
            )

            self._initialized = True
            logger.info(
                "Vector matcher initialized",
                model=EMBEDDING_MODEL,
                collection=COLLECTION_ATTACKS,
                doc_count=self._collection.count(),
            )

        except (RuntimeError, ValueError, OSError, TypeError, AttributeError) as e:
            logger.warning("Failed to initialize vector matcher", error=str(e))

    def _generate_id(self, text: str) -> str:
        """Generate a unique ID for a text document."""
        return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]

    def _embed(self, texts: list[str]) -> list[list[float]]:
        """Generate embeddings for texts.

        Args:
            texts: List of texts to embed.

        Returns:
            List of embedding vectors.
        """
        if not self._embedding_model:
            return []
        embeddings = self._embedding_model.encode(texts, convert_to_numpy=True)
        return embeddings.tolist()

    def add_attack(
        self,
        text: str,
        category: str,
        severity: ThreatSeverity | str = ThreatSeverity.HIGH,
        rule_id: str | None = None,
        description: str = "",
    ) -> bool:
        """Add a known attack pattern to the database.

        Args:
            text: Attack text/pattern.
            category: Attack category (e.g., "prompt_injection").
            severity: Severity level (ThreatSeverity enum or string like "high").
            rule_id: Optional rule ID for reference.
            description: Optional description.

        Returns:
            True if successfully added, False otherwise.
        """
        if not self._initialized or not self._collection:
            return False

        # Normalize severity to string value
        if isinstance(severity, ThreatSeverity):
            severity_str = severity.value
        elif isinstance(severity, str):
            severity_str = severity.lower()
        else:
            severity_str = "high"

        doc_id = self._generate_id(text)

        try:
            self._collection.add(
                ids=[doc_id],
                documents=[text],
                metadatas=[
                    {
                        "category": category,
                        "severity": severity_str,
                        "rule_id": rule_id or "",
                        "description": description,
                    }
                ],
            )
            return True
        except (RuntimeError, ValueError, OSError, TypeError, AttributeError) as e:
            logger.debug("Failed to add attack", error=str(e))
            return False

    def add_attacks_bulk(
        self,
        attacks: list[dict[str, Any]],
    ) -> int:
        """Add multiple attacks in bulk.

        Args:
            attacks: List of dicts with keys: text, category, severity, rule_id, description

        Returns:
            Number of attacks successfully added.
        """
        if not self._initialized:
            return 0

        added = 0
        for attack in attacks:
            severity_val = attack.get("severity", "medium")
            if isinstance(severity_val, str):
                try:
                    severity = ThreatSeverity(severity_val)
                except ValueError:
                    severity = ThreatSeverity.MEDIUM
            elif isinstance(severity_val, ThreatSeverity):
                severity = severity_val
            else:
                severity = ThreatSeverity.MEDIUM

            if self.add_attack(
                text=attack.get("text", ""),
                category=attack.get("category", "unknown"),
                severity=severity,
                rule_id=attack.get("rule_id"),
                description=attack.get("description", ""),
            ):
                added += 1
        return added

    def search(self, text: str, top_k: int = 5) -> list[VectorMatch]:
        """Search for similar attacks in the database.

        Args:
            text: Query text to search for.
            top_k: Maximum number of results to return.

        Returns:
            List of VectorMatch objects, sorted by similarity (highest first).
        """
        if not self._initialized or not self._collection or self._collection.count() == 0:
            return []

        try:
            # Generate embedding
            embeddings = self._embed([text])
            if not embeddings:
                return []

            # Query ChromaDB
            results = self._collection.query(
                query_embeddings=embeddings,
                n_results=min(top_k, self._collection.count()),
                include=["documents", "metadatas", "distances"],
            )

            matches: list[VectorMatch] = []
            if results and "ids" in results and results["ids"]:
                for i in range(len(results["ids"][0])):
                    distance = float(results["distances"][0][i])
                    # ChromaDB with cosine returns distance in [0, 2], convert to similarity
                    similarity = max(0.0, min(1.0, 1.0 - distance))

                    matches.append(
                        VectorMatch(
                            id=results["ids"][0][i],
                            content=results["documents"][0][i],
                            similarity=similarity,
                            metadata=results["metadatas"][0][i] if results["metadatas"] else {},
                            distance=distance,
                        )
                    )

            return sorted(matches, key=lambda m: m.similarity, reverse=True)

        except (RuntimeError, ValueError, OSError, TypeError, AttributeError) as e:
            logger.warning("Vector search failed", error=str(e))
            return []

    def evaluate(self, text: str) -> Verdict:
        """Evaluate text and return a verdict based on vector similarity.

        Args:
            text: Input text to evaluate.

        Returns:
            Verdict with decision based on similarity matches.
        """
        start_time = time.perf_counter()

        if not self._initialized:
            return Verdict(
                decision=ActionDecision.ALLOW,
                confidence=0.0,
                tier_source=TierSource.TIER1_VECTOR,
                threats=[],
                reason="Vector matcher not available",
                latency_ms=0.0,
            )

        matches = self.search(text, top_k=3)
        latency_ms = (time.perf_counter() - start_time) * 1000.0

        if not matches:
            return Verdict(
                decision=ActionDecision.ALLOW,
                confidence=0.10,
                tier_source=TierSource.TIER1_VECTOR,
                threats=[],
                reason="No similar patterns found in threat database",
                latency_ms=latency_ms,
            )

        # Get best match
        best_match = matches[0]

        # Determine severity and decision based on similarity
        if best_match.similarity >= self.critical_threshold:
            severity = ThreatSeverity.CRITICAL
            decision = ActionDecision.BLOCK
            confidence = best_match.similarity
        elif best_match.similarity >= self.high_threshold:
            severity = ThreatSeverity.HIGH
            decision = ActionDecision.BLOCK
            confidence = best_match.similarity
        elif best_match.similarity >= self.medium_threshold:
            severity = ThreatSeverity.MEDIUM
            decision = ActionDecision.ASK
            confidence = best_match.similarity
        else:
            return Verdict(
                decision=ActionDecision.ALLOW,
                confidence=1.0 - best_match.similarity,
                tier_source=TierSource.TIER1_VECTOR,
                threats=[],
                reason=f"Low similarity to known threats (max: {best_match.similarity:.2%})",
                latency_ms=latency_ms,
            )

        # Create threat match
        threat = ThreatMatch(
            rule_id=best_match.metadata.get("rule_id", "ADR-VEC-001"),
            rule_name=f"Vector Match: {best_match.metadata.get('category', 'unknown')}",
            category=best_match.metadata.get("category", "unknown"),
            severity=severity,
            matched_pattern=f"similarity={best_match.similarity:.2%}",
            matched_content=(
                best_match.content[:100] + "..."
                if len(best_match.content) > 100
                else best_match.content
            ),
        )

        return Verdict(
            decision=decision,
            confidence=confidence,
            tier_source=TierSource.TIER1_VECTOR,
            threats=[threat],
            reason=f"Similar to known attack pattern (similarity: {best_match.similarity:.2%})",
            latency_ms=latency_ms,
        )

    def clear(self) -> bool:
        """Clear all documents from the collection.

        Returns:
            True if successful, False otherwise.
        """
        if not self._initialized or not self._client:
            return False
        try:
            # Delete and recreate collection with consistent embedding function
            self._client.delete_collection(COLLECTION_ATTACKS)
            self._collection = self._client.get_or_create_collection(
                name=COLLECTION_ATTACKS,
                metadata={"hnsw:space": "cosine"},
                embedding_function=getattr(self, "_embedding_fn", None),
            )
            return True
        except (RuntimeError, ValueError, OSError, TypeError, AttributeError) as e:
            logger.warning("Failed to clear collection", error=str(e))
            return False

    @property
    def is_available(self) -> bool:
        """Returns True if the matcher is ready to use."""
        return self._initialized

    @property
    def document_count(self) -> int:
        """Returns the number of documents in the collection."""
        if not self._initialized or not self._collection:
            return 0
        return int(self._collection.count())

    def load_known_attacks(self) -> int:
        """Load all known attack patterns from the built-in dataset.

        Returns:
            Number of attacks loaded.
        """
        if not self._initialized:
            return 0

        try:
            from vinci_adr.tier1_fast.known_attacks import get_all_attacks
            attacks = get_all_attacks()
            return self.add_attacks_bulk(attacks)
        except ImportError:
            logger.warning("Known attacks module not found")
            return 0
