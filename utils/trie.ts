export class TrieNode {
  l: string;
  v: string;
  e: boolean;
  c: Map<string, TrieNode>;
  constructor(label = '', value = '') {
    this.l = label;
    this.v = value;
    this.e = false;
    this.c = new Map();
  }
}

export class Trie {
  private root: TrieNode;
  private cache: WeakMap<TrieNode, string[]>;
  private results: number;
  constructor(results = 25) {
    this.root = new TrieNode();
    this.cache = new WeakMap();
    this.results = results;
  }

  insert(id: string, value: string): void {
    let curr = this.root;
    const labels = id.split('.').reverse();
    for (const label of labels) {
      let next = curr.c.get(label);
      if (!next) {
        next = new TrieNode(label, value);
        curr.c.set(label, next);
      } else if (next.c.size === 1 && !next.e) {
        // Merge nodes with single children
        const [childLabel, childNode] = Array.from(next.c.entries())[0];
        next.l += `.${childLabel}`;
        next.c = childNode.c;
        next.e = childNode.e;
        next.v = childNode.v;
      }
      curr = next;
    }
    curr.v = value;
    curr.e = true;
  }

  lookup(id: string): string | undefined {
    return this._search(id)?.v;
  }

  search(query: string): string[] {
    const node = this._search(query);
    if (!node) return [];
    const cached = this.cache.get(node);
    if (cached) return cached;
    const nodes = this._collect(node, query);
    this.cache.set(node, nodes);
    return nodes.reverse();
  }

  save(): string { 
    const nodes: Record<string, unknown> = {};
    const visited: Set<TrieNode> = new Set();
    const traverse = (node: TrieNode, path: string[]) => {
      if (!visited.has(node)) {
        visited.add(node);
        const children = Object.fromEntries(
          Array.from(node.c.entries())
            .map(([key, child]) => [
              key,
              traverse(child, [...path, key])
            ])
            .filter(([, child]) => child !== null) // Filter out empty children
        );
        const nodeData: Record<string, unknown> = {
          l: node.l !== '' ? node.l : undefined, // Only include if not default
          v: node.v !== '' ? node.v : undefined, // Only include if not default
        };
        if (Object.keys(children).length > 0) {
          nodeData.c = children;
        }
        if (node.e) {
          nodeData.e = true;
        }
        nodes[path.join('.')] = nodeData;
      }
      return nodes[path.join('.')];
    };

    return JSON.stringify({r: traverse(this.root, [])}, (_key, value) =>
      value === undefined ? null : value
    );
  }

  load(trie: string): Trie {
    const data = JSON.parse(trie, (key, value) => 
      key === 'children' ? Object.fromEntries(value) : value
    );

    const root = new TrieNode(data.root.label, data.root.value);
    const nodes = new Map<string, TrieNode>();
    nodes.set('', root);

    const build = (path: string[], parent: TrieNode) => {
      const currPath = path.slice(0, -1).join('.');
      const currNode = nodes.get(currPath) || new TrieNode(path[path.length - 1], '');
      nodes.set(currPath, currNode);

      if (parent.e) {
        parent.c.set(path[path.length - 1], currNode);
      } else {
        parent.c.set(path[path.length - 1], build(path, parent));
      }

      return currNode;
    }

    build(Object.keys(data.root.children)[0].split('.'), root);

    return new Trie();
  }

  private _search(domain: string): TrieNode | null {
    let curr = this.root;
    const labels = domain.split('.').reverse();
    for (const label of labels) {
      const next = curr.c.get(label);
      if (!next) return null;
      curr = next;
    }
    return curr;
  }

  private _collect(node: TrieNode, query: string): string[] {
    const ids: string[] = [];
    this._index(node, query, ids);
    return ids;
  }

  private _index(node: TrieNode, id: string, ids: string[]): void {
    if (node.e && ids.length < this.results)
      ids.push(id);
    if (ids.length >= this.results)
      return;
    for (const [label, child] of node.c)
      this._index(child, `${id}.${label}`, ids);
  }
}
