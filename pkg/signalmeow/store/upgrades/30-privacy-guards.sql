-- v30 (compatible with v30+): Durable privacy guards and the storage manifest highwater
-- Older binaries would apply storage updates over protected imported privacy decisions.
CREATE TABLE signalmeow_privacy_guards (
    account_id       TEXT    NOT NULL,
    entity_kind      TEXT    NOT NULL CHECK ( entity_kind IN ('account', 'aci', 'pni') ),
    entity_id        TEXT    NOT NULL,
    field            TEXT    NOT NULL,
    local_present    BOOLEAN NOT NULL,
    local_value      bytea   NOT NULL,
    protected        BOOLEAN NOT NULL,
    armed_version    BIGINT  NOT NULL CHECK ( armed_version >= 0 ),
    remote_present   BOOLEAN NOT NULL DEFAULT false,
    remote_value     bytea,
    observed_version BIGINT,

    PRIMARY KEY (account_id, entity_kind, entity_id, field),
    FOREIGN KEY (account_id) REFERENCES signalmeow_device (aci_uuid) ON DELETE CASCADE ON UPDATE CASCADE
);
ALTER TABLE signalmeow_device ADD COLUMN storage_manifest_version BIGINT;
