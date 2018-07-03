return {
  {
    name = "2018-06-25-paseto-auth",
    up = [[
      CREATE TABLE IF NOT EXISTS paseto_keys(
        id uuid,
        consumer_id uuid,
        kid text,
        secret_key text,
        public_key text,
        created_at timestamp,
        PRIMARY KEY (id)
      );
      CREATE INDEX IF NOT EXISTS ON paseto_keys(kid);
      CREATE INDEX IF NOT EXISTS ON paseto_keys(consumer_id);
    ]],
    down = [[
      DROP TABLE paseto_keys;
    ]]
  },
}
