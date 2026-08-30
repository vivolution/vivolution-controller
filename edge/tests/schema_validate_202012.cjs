#!/usr/bin/env node
"use strict";

const fs = require("fs");
const Ajv2020 = require("ajv/dist/2020").default;

if (process.argv.length !== 4) {
  process.stderr.write("usage: schema_validate_202012.cjs SCHEMA INSTANCE\n");
  process.exit(2);
}

const schema = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const instance = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: false, validateFormats: false });
if (!ajv.validateSchema(schema)) {
  process.stderr.write(JSON.stringify(ajv.errors, null, 2) + "\n");
  process.exit(1);
}
const validate = ajv.compile(schema);
if (!validate(instance)) {
  process.stderr.write(JSON.stringify(validate.errors, null, 2) + "\n");
  process.exit(1);
}
process.stdout.write("DRAFT_2020_12_VALID\n");
