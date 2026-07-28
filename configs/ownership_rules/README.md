# Ownership scoring rules

`v1.json` preserves the first-version weights from the product specification. `v2.json` adds
bounded certificate-transparency and exact public-RDAP registrant corroboration while retaining the
same no-auto-authorization boundary. The engine stores every applied signal as an Evidence row; the
aggregate score alone is never treated as proof or permission to scan.
