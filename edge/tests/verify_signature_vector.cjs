#!/usr/bin/env node
"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

if (process.argv.length !== 5) {
  process.stderr.write("usage: verify_signature_vector.cjs VECTOR CANONICAL_MANIFEST DOMAIN_HEX\n");
  process.exit(2);
}

const vector = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const canonical = fs.readFileSync(process.argv[3]);
const domain = Buffer.from(process.argv[4], "hex");
const message = Buffer.concat([domain, canonical]);
const publicRaw = Buffer.from(vector.publicKeyRawBase64, "base64");
const spki = Buffer.concat([
  Buffer.from("302a300506032b6570032100", "hex"),
  publicRaw,
]);
const publicKey = crypto.createPublicKey({ key: spki, format: "der", type: "spki" });
const signature = Buffer.from(vector.signatureBase64, "base64");
if (!crypto.verify(null, message, publicKey, signature)) {
  process.stderr.write("Ed25519 vector verification failed\n");
  process.exit(1);
}
process.stdout.write("ED25519_VECTOR_VALID\n");
