import type {WebAppManifest} from './web.ts';

/**
 * Represents a web app.
 */
export type UbiApp = {
  id: number,
  url: string,
  name: string,
  desc: string,
  logo: string,
  icon: string,
  keywords: string[],
  section: UbiAppSection,
  location?: UbiAppLocation,
  manifest: WebAppManifest,
}

/**
 * Represents a section of web app categories.
 */
export enum UbiAppSection {
  Arc = 'archival',
  Com = 'commercial',
  Cul = 'cultural',
  Edu = 'educational',
  Env = 'environmental',
  Fin = 'financial',
  Ind = 'industrial',
  Int = 'international',
  Jud = 'judicial',
  Med = 'medical',
  Nat = 'national',
  Per = 'personal',
  Pol = 'political',
  Rec = 'recreational',
  Soc = 'social',
  Spi = 'spiritual',
  Tec = 'technical',
  Voc = 'vocational',
}

/**
 * Represents the location of the web app host
 */
export interface UbiAppLocation {
  coords: [number, number],
  country: string,
  region: string,
  city: string,
  port: number,
  ip: number,
}
