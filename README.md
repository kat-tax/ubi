# UBI

The Ultimate Web Directory

## Process

1. Pull index from [shodan](https://shodan.io)
2. For each service in the index:
  * Parse metatags in recorded HTML
  * If present, parse JSON-LD in recorded HTML (via https://github.com/rubensworks/jsonld-streaming-serializer.js)
  * If present, download + parse manifest using path in `rel="manifest"`
  * Determine *name* using the following sources, if valid, in order:
    - manifest `title`
    - JSON-LD `name`
    - meta `site_name`
    - meta `title`
    > if pipe is present, split on pipe and take first element)
    > Disqualify name source if:
      - empty after trimming
      - matches a starter name:
        - `Create React App`
        - `App`
  * Determine *description* using the following sources, if valid, in order:
    - manifest `description`
    - JSON-LD `description`
    - meta `description`
    > Disqualify description source if:
      - empty after trimming
      - matches title
  * Determine *icon* using the following sources, if valid, in order:
    - manifest `icons`
    - meta `icon`
    - favicon
    > Choose largest icon from source if multiple are present
  * Build new manifest merging existing manifest (if present) with new manifest
  * Pin manifest, icon, and screenshot to IPFS
3. Build a trie for all services using the domain as the key w/ leaf node to ipfs hash
4. Compress trie, upload to IPFS, and serve via IPNS