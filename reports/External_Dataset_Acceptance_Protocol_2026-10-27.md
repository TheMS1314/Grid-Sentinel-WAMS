# External dataset acceptance — frozen TCP capture-level evaluation

Use this tool to evaluate independently sourced labeled PCAP/PCAPNG captures without tuning Grid Sentinel's offline frozen TCP rule.

1. Obtain raw captures through the publisher's authorized download. Keep source data outside Git.
2. Build a manifest with exact capture filenames, externally verified SHA-256 digests, scenario-level attack/benign truth, declared family, and whether **TCP destination-port reconnaissance** is genuinely in-scope.
3. If the publisher independently documents benign exposure, provide `verified_benign_seconds` no longer than the capture span. Otherwise omit it.
4. Run `python external_capture_acceptance.py /path/to/manifest.json /private/raw/capture_directory`.
5. Save the JSON, manifest, publisher provenance and checksum evidence together for review; **do not retune** the model after inspecting the results.

Schema example (placeholders, **not experiment results**):

```json
{
  "schema_version": 1,
  "captures": [
    {
      "path": "normal.pcap",
      "sha256": "64_lowercase_hex_digits",
      "truth": "benign",
      "family": "normal",
      "tcp_scan_in_scope": false
    },
    {
      "path": "scan.pcapng",
      "sha256": "64_lowercase_hex_digits",
      "truth": "attack",
      "family": "tcp_port_scan",
      "tcp_scan_in_scope": true
    }
  ]
}
```

The tool fails closed for corrupted digests, unsafe paths, unsupported inputs, duplicate captures and inflated benign exposure. It outputs capture-level review fractions, not true-positive event counts, packet classification or F1. Unsupported attack families are counted as explicit abstentions. A 24-hour false-alert target is **not assessable** until sufficient verified benign time is supplied.

CIC Modbus 2023 provides PCAP and time-stamped attack logs, but official access presently requires a publisher-hosted researcher form; no source bytes or new CIC accuracy claims have been obtained. For true event-level recall, separate attack-log alignment and independently verified times are still required. No paper written.
