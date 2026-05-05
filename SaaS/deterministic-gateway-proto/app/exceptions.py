"""
Custom exceptions for the AI Policy Compiler.
Fail-fast design: specific errors, no silent fallbacks.
"""


class PolicyCompilerError(Exception):
    """Base exception for all pipeline errors."""
    pass


class LLMExtractionError(PolicyCompilerError):
    """Raised when LLM returns malformed or unparseable JSON."""
    pass


class SchemaValidationError(PolicyCompilerError):
    """Raised when extracted IR fails schema validation."""
    pass


class EntityResolutionError(PolicyCompilerError):
    """Raised when a principal or resource cannot be resolved in the shadow catalog."""
    pass


class InvalidActionError(PolicyCompilerError):
    """Raised when the action_intent is not in the allowed set."""
    pass


class PolicyCompilationError(PolicyCompilerError):
    """Raised when Cedar policy generation fails."""
    pass


class VerificationError(PolicyCompilerError):
    """Raised when Cedar CLI verification fails (retryable)."""
    pass


class MaxRetriesExceededError(PolicyCompilerError):
    """Raised when the retry loop exhausts all allowed attempts."""
    pass


class RoutingError(PolicyCompilerError):
    """Raised when the confidence router rejects a policy."""
    pass


class ReviewError(PolicyCompilerError):
    """Raised when a review operation fails."""
    pass


class ConflictDetectionError(PolicyCompilerError):
    """Raised when policy conflict detection encounters an error."""
    pass


class DeploymentError(PolicyCompilerError):
    """Raised when policy deployment or rollback fails."""
    pass


class CatalogError(PolicyCompilerError):
    """Raised when catalog operations fail."""
    pass


class ControlExtractionError(PolicyCompilerError):
    """Raised when regulatory control extraction fails."""
    pass


class ControlValidationError(PolicyCompilerError):
    """Raised when ControlIR fails validation."""
    pass


class CatalogEnrichmentRequired(PolicyCompilerError):
    """Raised when entities need catalog expansion before processing."""
    pass
