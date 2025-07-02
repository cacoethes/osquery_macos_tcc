# osquery_macos_tcc

An osquery extension that exposes data from the macOS TCC (Transparency,
Consent and Control) database. The extension adds a new table named
`macos_tcc` that aggregates both the system level database and the databases
for each local user.

---

## Table: `macos_tcc`

The table has the following columns:

| column                              | type   | description                               |
|-------------------------------------|--------|-------------------------------------------|
| `type`                              | TEXT   | `user` or `system` database record        |
| `username`                          | TEXT   | macOS account owning the record           |
| `service`                           | TEXT   | TCC service name                          |
| `client`                            | TEXT   | bundle identifier or absolute path        |
| `client_type`                       | INTEGER| numeric client type value                 |
| `auth_value`                        | INTEGER| authorization result                      |
| `auth_reason`                       | INTEGER| reason code for the authorization result  |
| `auth_version`                      | INTEGER| authorization version                     |
| `csreq`                             | TEXT   | binary code signing requirement (hex)     |
| `policy_id`                         | TEXT   | policy identifier                         |
| `indirect_object_identifier_type`   | INTEGER| indirect object type                      |
| `indirect_object_identifier`        | TEXT   | indirect object identifier                |
| `indirect_object_code_identity`     | TEXT   | indirect code identity (hex)              |
| `flags`                             | INTEGER| flags recorded in the TCC entry           |
| `last_modified`                     | INTEGER| UNIX epoch when entry was last modified   |

---

## Building

The Makefile builds a statically linked darwin/amd64 binary. The default
target produces a release build without debug logging:

```bash
make
```

The binary will be written to `build/osquery-macos-tcc`.

To build with debug logging enabled use:

```bash
make debug
```

which outputs `build/osquery-macos-tcc-debug`.

---

## Running

The resulting binary is an osquery extension. Run it alongside `osqueryi` or
`osqueryd` and pass it as an extension:

```bash
osqueryi --extension build/osquery-macos-tcc
```

The extension will automatically locate the osquery extension socket unless an
explicit path is provided with `--socket` or the `OSQUERY_EXTENSION_SOCKET`
environment variable.

---

## Example query

After starting `osqueryi` with the extension you can inspect the collected TCC
entries. A small sample query might look like:

```sql
select type, username, service, client, auth_value
from macos_tcc
limit 3;
```

Example output:

```
osquery> select type, username, service, client, auth_value from macos_tcc limit 3;
| type   | username | service                      | client                        | auth_value |
|--------|----------|------------------------------|-------------------------------|-----------|
| user   | alice    | kTCCServiceMicrophone        | /Applications/Skype.app       | 2         |
| user   | bob      | kTCCServiceCamera            | /Applications/zoom.us.app     | 0         |
| system |          | kTCCServiceSystemPolicyAllFiles | com.apple.MobileTimeMachine | 2         |
```

---
