# Persona Messages (Draft)

This directory is for concise inter-persona coordination after the user
approves the handoff.

After writing `analysis.md`, each persona must route every question it proposed
for another persona into this directory. The recipient answers all routed
questions in its private `response.md`; recipients do not read the sender's
private analysis.

Name each message:

```text
<sender>-to-<recipient>-<topic>.md
```

Each message should contain:

- sender and intended recipient;
- a short question, clarification, or evidence lead;
- the exact authorized snapshot or rootfs path supporting the lead;
- the requested response, if any.

Do not use messages as substitute reports. Do not include internet-derived or
otherwise unauthorized information. Recipients must verify factual claims
against the supplied snapshot or rootfs before relying on them.
