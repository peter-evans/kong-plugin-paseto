return {
  {
    name = "2018-06-25-paseto-auth",
    up = [[
      CREATE TABLE IF NOT EXISTS paseto_keys(
        id uuid,
        consumer_id uuid REFERENCES consumers (id) ON DELETE CASCADE,
        kid text UNIQUE,
        secret_key text,
        public_key text,
        created_at timestamp without time zone default (CURRENT_TIMESTAMP(0) at time zone 'utc'),
        PRIMARY KEY (id)
      );
      DO $$
      BEGIN
        IF (SELECT to_regclass('paseto_keys_key')) IS NULL THEN
          CREATE INDEX paseto_keys_key ON paseto_keys(kid);
        END IF;
        IF (SELECT to_regclass('paseto_keys_consumer_id')) IS NULL THEN
          CREATE INDEX paseto_keys_consumer_id ON paseto_keys(consumer_id);
        END IF;
      END$$;
    ]],
    down = [[
      DROP TABLE paseto_keys;
    ]]
  },
}
