package io.github.lecodev26.nexusq;

/** Error raised when a NEXUS-Q operation fails. */
public class NexusqException extends RuntimeException {
    public NexusqException(String message) {
        super(message != null ? message : "NEXUS-Q operation failed");
    }
}
