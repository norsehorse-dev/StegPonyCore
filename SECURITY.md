# Security

Report vulnerabilities privately to NorseHorse@norsehor.se. An age-encrypted report is welcome; the public key is on the StegPony site.

Things that count as security bugs here, beyond the usual memory and crypto bugs:

- Anything that lets someone without the secret tell a StegPony image from an untouched one more reliably than the steganalysis limits documented in FORMAT.md and the app's help.
- Anything that tells a slot holding a payload or decoy apart from a filler slot.
- Anything in the output that depends on the secret, the payload length beyond its bucket, or the platform that wrote it.
- A reveal that behaves differently (time, errors, output) for "wrong key" and "no payload" in a way an observer could use.
