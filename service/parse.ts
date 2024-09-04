import {Trie} from '../utils/trie.ts';
import {JsonStream} from '../utils/json.ts';
import {extractProps} from '../utils/html.ts';
import {fetchManifest} from '../utils/manifest.ts';
import {SEPARATORS, IGNORED_APPS, IGNORED_NAMES, IGNORED_DOMAINS} from '../utils/lists.ts';
import {UbiAppSection} from '../models/ubi.ts';

import type {Props} from '../utils/html.ts';
import type {UbiApp} from '../models/ubi.ts';
import type {Banner} from '../models/shodan.ts';
import type {WebAppManifest} from '../models/web.ts';

export async function parse() {
  let count = 0;
  const trie = new Trie();
  const hits = new Map<string, number>();
  const file = await Deno.open('us.json', {read: true});
  const reader = file.readable.getReader();

  // Handle the shodan stream
  const stream = JsonStream({object: o => {
    const app = parseApp(o as unknown as Banner);
    if (!app) return;
    if (!hits.has(app.url))
      hits.set(app.url, 0);
    hits.set(app.url, (hits.get(app.url) ?? 0) + 1);
    trie.insert(app.url, app.id.toString());
    count++;
    console.log('>>>', count, app.url, hits.get(app.url), app.name);
  }});

  // Stream the shodan data
  while(true) {
    const {done, value} = await reader.read();
    if (done) break;
    stream.chunk(new TextDecoder().decode(value));
  }

  // Display the hits in ascending order
  const sortedHits = Array.from(hits.entries()).sort((a, b) => a[1] - b[1]);
  for (const [url, count] of sortedHits) {
    if (count > 1) {
      console.log(url, count);
    }
  }

  // Save trie
  Deno.writeTextFileSync('trie.json', trie.save());
}

function parseApp(entry: Banner): UbiApp | null {
  const props = extractProps(entry.http?.html);
  const parse = parseProps(entry, props, {});
  const host = parseHost(entry);
  if (!host || !parse.name || ignored(parse.name, IGNORED_APPS))
    return null;
  return {
    id: entry.hash,
    url: host,
    name: parse.name,
    desc: parse.desc,
    logo: parse.logo,
    icon: entry.http?.favicon?.data ?? '',
    keywords: props.keywords?.split(',').map(s => s.trim()) ?? [],
    section: UbiAppSection.Per,
    manifest: {},
  };
}

function parseHost(entry: Banner) {
  return entry.domains.find(d =>
    !IGNORED_DOMAINS.some(i => d.includes(i))) ?? '';
}

function parseProps(entry: Banner, props: Props, manifest: WebAppManifest) {
  let name = choose([
    manifest.name,
    props.application_name,
    props['application-name'],
    props['og:site_name'],
    props['og:title'],
    props.title,
    entry.title,
  ]);

  let desc = choose([
    manifest.description,
    props['og:description'],
    props.description,
  ]);

  const logo = choose([
    manifest.icons?.pop()?.src,
    props['og:image'],
  ]);

  const [_name, _desc] = split(name);
  name = _name.trim();
  desc = _desc && (!desc || desc === name)
    ? _desc.trim()
    : desc;

  return {name, desc, logo};
}

function choose(sources: (string | undefined)[]): string {
  for (const source of sources)
    if (valid(source))
      return source.trim();
  return '';
}

function valid(input?: string): input is string {
  if (!input) return false;
  if (input.trim().length === 0) return false;
  if (ignored(input, IGNORED_NAMES)) return false;
  return true;
}

function split(input: string) {
  const separator = SEPARATORS.find(s => input.includes(s));
  if (!separator) return [input];
  const [name, ...desc] = input.split(separator);
  return [
    name.trim(),
    desc.join(separator).trim(),
  ];
}

function ignored(name: string, list: [string, boolean][]) {
  if (name.trim().length === 0) return true;
  return list.some(([app, exact]) =>
    exact ? app === name : name.includes(app));
}
