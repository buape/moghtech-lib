-- mogh_auth 5.0 renamed "api keys v2" to signing keys. The kind of
-- an api key is stored by its ApiKeyKind name: the key + secret ones
-- were 'V1', the signing keys (a public key, requests signed with
-- the private key) 'V2'.
UPDATE api_keys SET kind = 'ApiKey' WHERE kind = 'V1';
UPDATE api_keys SET kind = 'SigningKey' WHERE kind = 'V2';
