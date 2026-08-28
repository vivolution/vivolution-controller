ARG BASE_IMAGE
FROM ${BASE_IMAGE}

# Migrations still run because deployment overrides the entrypoint with Python.
# The web service deliberately fails so automatic release recovery is exercised.
ENTRYPOINT ["/bin/false"]
