import { describe, expect, it } from 'vitest';
import { aBase32, claveNueva, deBase32, hotp, segundosRestantes, totp } from '../src/core/totp';

const RFC = new TextEncoder().encode('12345678901234567890');

describe('totp', () => {
  it('cumple los vectores de RFC 4226', async () => {
    expect(await hotp(RFC, 0)).toBe('755224');
    expect(await hotp(RFC, 1)).toBe('287082');
    expect(await hotp(RFC, 9)).toBe('520489');
  });

  it('cumple el vector de RFC 6238 con 8 cifras y 30 s', async () => {
    expect(await totp(RFC, 59_000, 30, 8)).toBe('94287082');
  });

  it('cambia cada 10 segundos', async () => {
    expect(await totp(RFC, 10_000)).toBe(await totp(RFC, 19_999));
    expect(await totp(RFC, 10_000)).not.toBe(await totp(RFC, 20_000));
    expect(segundosRestantes(12_500)).toBeCloseTo(7.5);
  });

  it('codifica y decodifica Base32', () => {
    expect(aBase32(RFC)).toBe('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
    expect(deBase32('gezd gnbv-gy3t qojq gezd gnbv gy3t qojq')).toEqual(RFC);
    expect(deBase32('ABC1')).toBeNull();
    expect(deBase32(claveNueva())?.length).toBe(20);
  });
});
