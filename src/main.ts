import './style.css';

import { PERIODO, claveNueva, deBase32, segundosRestantes, totp } from './core/totp';
import { VERSION } from './version';

const CLAVE_GUARDADO = 'mcl-autenticator-code';

function leerClave(): string {
  try {
    const guardada = localStorage.getItem(CLAVE_GUARDADO);
    if (guardada && deBase32(guardada)) return guardada;
  } catch {
    /* sin almacenamiento: se usa una clave temporal */
  }
  const nueva = claveNueva();
  guardarClave(nueva);
  return nueva;
}

function guardarClave(clave: string): void {
  try {
    localStorage.setItem(CLAVE_GUARDADO, clave);
  } catch {
    /* sin almacenamiento */
  }
}

let clave = leerClave();

const raiz = document.getElementById('app')!;
raiz.innerHTML = `
  <main class="tarjeta">
    <h1>🔐 Autenticator Code</h1>
    <p class="sub">Código de 6 cifras · cambia cada ${PERIODO} s</p>
    <button class="codigo" id="codigo" title="Toca para copiar" aria-live="polite">------</button>
    <div class="barra"><div id="relleno"></div></div>
    <p class="estado" id="estado">&nbsp;</p>
    <details>
      <summary>🔑 Clave secreta</summary>
      <p class="ayuda">Usa la misma clave en otro dispositivo o app de autenticación (TOTP, SHA-1, 6 cifras, ${PERIODO} s) para obtener los mismos códigos.</p>
      <input id="clave" spellcheck="false" autocomplete="off" />
      <div class="botones">
        <button id="guardar">Guardar</button>
        <button id="nueva">Clave nueva</button>
      </div>
    </details>
    <footer>Autenticator Code · v${VERSION}</footer>
  </main>
`;

const elCodigo = document.getElementById('codigo') as HTMLButtonElement;
const elRelleno = document.getElementById('relleno') as HTMLDivElement;
const elEstado = document.getElementById('estado') as HTMLParagraphElement;
const elClave = document.getElementById('clave') as HTMLInputElement;

let codigoActual = '';
let contadorActual = -1;
let avisoHasta = 0;

const formatear = (c: string) => `${c.slice(0, 3)} ${c.slice(3)}`;

function avisar(texto: string): void {
  elEstado.textContent = texto;
  avisoHasta = Date.now() + 2000;
}

function mostrarClave(): void {
  elClave.value = clave.replace(/(.{4})/g, '$1 ').trim();
}

async function actualizar(): Promise<void> {
  const ahora = Date.now();
  const contador = Math.floor(ahora / 1000 / PERIODO);
  if (contador !== contadorActual) {
    contadorActual = contador;
    codigoActual = await totp(deBase32(clave)!, ahora);
    elCodigo.textContent = formatear(codigoActual);
  }
  const resta = segundosRestantes(ahora);
  elRelleno.style.width = `${(resta / PERIODO) * 100}%`;
  elRelleno.classList.toggle('poco', resta <= 3);
  if (ahora > avisoHasta) elEstado.textContent = `Quedan ${Math.ceil(resta)} s`;
}

function bucle(): void {
  void actualizar();
  requestAnimationFrame(bucle);
}

elCodigo.addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(codigoActual);
    avisar('✅ Código copiado');
  } catch {
    avisar('No se pudo copiar');
  }
});

document.getElementById('guardar')!.addEventListener('click', () => {
  const bytes = deBase32(elClave.value);
  if (!bytes || bytes.length < 10) {
    avisar('⚠️ Clave no válida (Base32, mínimo 16 letras)');
    return;
  }
  clave = elClave.value.toUpperCase().replace(/[\s\-=]/g, '');
  guardarClave(clave);
  contadorActual = -1;
  mostrarClave();
  avisar('✅ Clave guardada');
});

document.getElementById('nueva')!.addEventListener('click', () => {
  if (!confirm('¿Crear una clave nueva? Los códigos dejarán de coincidir con la clave anterior.')) return;
  clave = claveNueva();
  guardarClave(clave);
  contadorActual = -1;
  mostrarClave();
  avisar('✅ Clave nueva creada');
});

mostrarClave();
bucle();

if (import.meta.env.PROD && 'serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').catch(() => undefined);
  });
}
