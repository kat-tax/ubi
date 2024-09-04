import type {WebAppManifest} from '../models/web.ts';

export async function fetchManifest(ip: number, url?: string): Promise<WebAppManifest> {
  if (!url) return {};
  const base = ip.toString().padStart(15, '0');
  const addr = `http://${base}${url}`;
  return await fetch(addr).then(res => res.json());
}
