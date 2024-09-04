import * as cheerio from 'cheerio';

export type Props = {
  [key: string]: string | undefined,
}

export function extractProps(html?: string): Props {
  if (!html) return {};
  const $ = cheerio.load(html);
  const o: Props = {};
  try {
    o.title = $('title').text();
    o.description = $('meta[name="description"]').attr('content');
    o.favicon = $('link[rel="icon"]').attr('href');
    o.manifest = $('link[rel="manifest"]').attr('href');
    for (const tag of $('meta').toArray()) {
      const name = $(tag).attr('name');
      const prop = $(tag).attr('property');
      if (name) o[name] = $(tag).attr('content');
      if (prop) o[prop] = $(tag).attr('content');
    }
    return o;
  } catch (error) {
    console.error(error);
    return {};
  }
}
