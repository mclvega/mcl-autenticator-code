/** Códigos TOTP (RFC 6238) con HMAC-SHA1, 6 cifras y un periodo de 10 segundos. */

export const PERIODO = 10;
export const CIFRAS = 6;

const ALFABETO = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Convierte bytes a Base32 (sin relleno). */
export function aBase32(bytes: Uint8Array): string {
  let bits = 0;
  let valor = 0;
  let salida = '';
  for (const b of bytes) {
    valor = (valor << 8) | b;
    bits += 8;
    while (bits >= 5) {
      salida += ALFABETO[(valor >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) salida += ALFABETO[(valor << (5 - bits)) & 31];
  return salida;
}

/** Lee una clave Base32 (ignora espacios, guiones y el relleno). Devuelve null si no es válida. */
export function deBase32(texto: string): Uint8Array | null {
  const limpio = texto.toUpperCase().replace(/[\s\-=]/g, '');
  if (!limpio) return null;
  let bits = 0;
  let valor = 0;
  const salida: number[] = [];
  for (const c of limpio) {
    const i = ALFABETO.indexOf(c);
    if (i < 0) return null;
    valor = (valor << 5) | i;
    bits += 5;
    if (bits >= 8) {
      salida.push((valor >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(salida);
}

/** Clave aleatoria nueva de 20 bytes, en Base32. */
export function claveNueva(): string {
  return aBase32(crypto.getRandomValues(new Uint8Array(20)));
}

/** Código HOTP para un contador. */
export async function hotp(clave: Uint8Array, contador: number, cifras = CIFRAS): Promise<string> {
  const mensaje = new Uint8Array(8);
  let c = contador;
  for (let i = 7; i >= 0; i--) {
    mensaje[i] = c & 255;
    c = Math.floor(c / 256);
  }
  const llave = await crypto.subtle.importKey('raw', new Uint8Array(clave), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const firma = new Uint8Array(await crypto.subtle.sign('HMAC', llave, mensaje));
  const desfase = firma[firma.length - 1] & 15;
  const numero =
    ((firma[desfase] & 127) << 24) | (firma[desfase + 1] << 16) | (firma[desfase + 2] << 8) | firma[desfase + 3];
  return String(numero % 10 ** cifras).padStart(cifras, '0');
}

/** Código TOTP para un instante (en milisegundos). */
export function totp(clave: Uint8Array, ahoraMs: number, periodo = PERIODO, cifras = CIFRAS): Promise<string> {
  return hotp(clave, Math.floor(ahoraMs / 1000 / periodo), cifras);
}

/** Segundos que le quedan al código actual. */
export function segundosRestantes(ahoraMs: number, periodo = PERIODO): number {
  return periodo - ((ahoraMs / 1000) % periodo);
}
