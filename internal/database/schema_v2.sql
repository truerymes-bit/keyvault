DROP INDEX api_keys_email_provider_fingerprint;

CREATE INDEX api_keys_email_fingerprint ON api_keys (email, fingerprint);
