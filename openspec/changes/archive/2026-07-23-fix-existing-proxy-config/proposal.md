# Don't silently discard proxy settings when a hand-written Caddyfile exists

## Why

When the installer finds a reverse-proxy configuration it did not generate, it refuses to
touch it — correctly, since clobbering an operator's hand-written config would be worse.
But it bails *after* the wizard has already collected the site, the reach, and any CIDR
restriction, and it says nothing about those answers being dropped. Observed on a real
install:

```
install.sh: /etc/caddy/Caddyfile already proxies abyssum-web (127.0.0.1:8000); leaving it as-is.
```

The operator answered three questions and every answer was discarded in silence. That is the
same defect this capability was just corrected for — ask a question, then ignore the answer —
and it also puts the installer at odds with canon, which says selecting the proxy applies the
chosen reach and CIDR restriction at the proxy.

## What Changes

- Not overwriting a configuration the installer did not generate becomes **explicit in the
  spec** rather than an unstated behavior.
- When such a configuration blocks the selected settings, the installer SHALL **say so** and
  state how to apply them, instead of reporting success-ish and moving on.
- Interactively, the installer MAY **offer to replace** the existing configuration, backing
  it up first.
- A `--force-proxy` flag lets a scripted install take the file over deliberately, with a
  timestamped backup; if the generated config then fails validation, the backup is restored.

## Out of scope

Merging into an existing configuration. Editing someone's hand-written Caddyfile in place is
guesswork; replace-with-backup or leave-and-report are the two honest options.
