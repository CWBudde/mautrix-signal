-- v29 (compatible with v29+): Store derived storage service keys
-- Older binaries would derive from a stale master key next to a newer derived key.
ALTER TABLE signalmeow_device ADD COLUMN storage_service_key bytea;
