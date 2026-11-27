// Manifest: every file the patcher reads or produces, and where it comes from.
// One list drives the checklist on the page. Hashes and sizes only; no game data.
//
// kind:
//   'input'        captured from the user's game folder or CD. Gets a checklist row.
//   'derived'      not a file on a normal install; produced by the build step from
//                  a captured input. Listed for transparency; never blocks Build.
//   'out-of-scope' not read by the text-table patcher. Listed, never captured.
//
// Paths are relative to the game folder and use forward slashes. The page matches
// captured files by base name (case-insensitive), so a folder picked at the top
// level or at DBDAT works.
//
// Sources, with the file they were taken from:
//   sha256 + name list ........ cli/pm99patch/edition.c, cli/pm99db/pm99db.c
//   sizes ..................... reference game copy (base-clean DBDAT listing) and
//                               build/pm99-textdb-release-20261121k/calendar-compiled
//   calendar derivation ....... docs/CALENDAR_HOWTO.md (calendar_tables export/compile
//                               from MANAGPRE.EXE), core/textdb/calendar/calendar_tables.h
//   TEXTOS/*.30 derivation .... TEXTDB/textmap.tsv (PAISES.30 -> text\381434.tsv, etc.),
//                               docs/TEXT_DB_GUIDE.md, docs/TEXT_DB_FIELDS.md
//   FECHCONV.30 origin ........ docs/CALENDAR_HOWTO.md (original CD file), cli/pm99patch/edition.c
//
// `confirmed`:
//   'confirmed'      source named in code or in a file in the release and checked here
//   'docs'           source stated in the docs only; not re-verified on a copy here
//   'UNCONFIRMED'    source could not be confirmed; see NOTES.md

export const MANIFEST_VERSION = 1;

export const MANIFEST = Object.freeze([
  // ---- inputs the user supplies ------------------------------------------------
  {
    id: 'managpre',
    kind: 'input',
    path: 'MANAGPRE.EXE',
    role: 'Game program; identifies the edition and is the source of the calendar tables',
    required: true,
    sha256: '01b845f7dc728e3813968bed51ff24810fde556fab395e97ca7649c57ee53158',
    size: 3442176,
    source: 'Game install (root folder).',
    confirmed: 'confirmed',
  },
  {
    id: 'jug',
    kind: 'input',
    path: 'DBDAT/JUG98030.FDI',
    role: 'Player database (container)',
    required: true,
    sha256: '95641e9d7fc0adb673045d43223d0ce7cfca531cd451f2f33e43425b05452844',
    size: 3847087,
    source: 'Game install, DBDAT folder.',
    confirmed: 'confirmed',
  },
  {
    id: 'eq',
    kind: 'input',
    path: 'DBDAT/EQ98030.FDI',
    role: 'Club, roster and team database (container)',
    required: true,
    sha256: 'e095cb47ffdb6c8edf384983545124eb514d044fa4f0ce7d924b6bfe13252a5c',
    size: 1097585,
    source: 'Game install, DBDAT folder.',
    confirmed: 'confirmed',
  },
  {
    id: 'ent',
    kind: 'input',
    path: 'DBDAT/ENT98030.FDI',
    role: 'Manager and staff database (container)',
    required: true,
    sha256: '729e486b441131c07dcbd3f6ba962587333459d8639329249646a86dd9ee3238',
    size: 159249,
    source: 'Game install, DBDAT folder.',
    confirmed: 'confirmed',
  },
  {
    id: 'textos',
    kind: 'input',
    path: 'DBDAT/TEXTOS.PKF',
    role: 'Packed text catalogue: name lists (PAISES, NOMBRES, APELLIDO and 245 others)',
    required: true,
    sha256: '7ba24d8539bb6e3e926e2061a357d1a4baf4f26f23040fbd1156095794ae8682',
    size: 398429,
    source: 'Game install, DBDAT folder.',
    confirmed: 'confirmed',
  },
  {
    id: 'fechconv',
    kind: 'input',
    path: 'DBDAT/FECHCONV.30',
    role: 'International call-date file. OPTIONAL: if you do not have it, everything else still works; you only lose the stock comparison for the international dates (they can be generated from the table). Checked when given.',
    required: false,
    sha256: 'bafc57765d10a508138ebebc7ceb7e0fd00581bee8a02e7ad561bc9c7150920c',
    size: 1543,
    source:
      'Original CD media (docs/CALENDAR_HOWTO.md: "the original CD file"). ' +
      'NOT present in the reference hard-disk install. Whether a normal install copies it to DBDAT: UNCONFIRMED.',
    confirmed: 'docs',
  },

  // ---- produced by the build step; not captured -------------------------------
  {
    id: 'calendar',
    kind: 'derived',
    path: 'calendar.pmc',
    role: 'Opening season calendar package (16,500 bytes)',
    required: false,
    sha256: '542f237822016e1a58a7c9ea3d08a7186063ea2f26b6cd7afc4c48f82a57a88c',
    size: 16500,
    source:
      'Compiled from calendar tables exported from MANAGPRE.EXE (docs/CALENDAR_HOWTO.md export and compile commands). ' +
      'No calendar.pmc file is on the reference install. Checked after a build, not captured.',
    confirmed: 'docs',
  },
  {
    id: 'paises',
    kind: 'derived',
    path: 'DBDAT/TEXTOS/PAISES.30',
    role: 'English country list (row index is the nationality code)',
    required: false,
    sha256: null,
    size: null,
    source:
      'Text entry inside TEXTOS.PKF (TEXTDB/textmap.tsv maps PAISES.30 to text\\381434.tsv). ' +
      'The link from the file name to the entry is from docs; not re-verified on a copy here.',
    confirmed: 'docs',
  },
  {
    id: 'nombres',
    kind: 'derived',
    path: 'DBDAT/TEXTOS/NOMBRES.30',
    role: 'First-name pool',
    required: false,
    sha256: null,
    size: null,
    source: 'Text entry inside TEXTOS.PKF (docs/TEXT_DB_GUIDE.md). Not re-verified here.',
    confirmed: 'docs',
  },
  {
    id: 'apellido',
    kind: 'derived',
    path: 'DBDAT/TEXTOS/APELLIDO.30',
    role: 'Surname pool',
    required: false,
    sha256: null,
    size: null,
    source: 'Text entry inside TEXTOS.PKF (docs/TEXT_DB_GUIDE.md). Not re-verified here.',
    confirmed: 'docs',
  },

  // ---- out of scope: listed, never captured ----------------------------------
  { id: 'oos-minifoto', kind: 'out-of-scope', path: 'DBDAT/MINIFOTO.PKF', role: 'Player photos (catalogue)', required: false, sha256: null, size: null, source: 'Photos are out of scope for now.', confirmed: 'confirmed' },
  { id: 'oos-miniesc', kind: 'out-of-scope', path: 'DBDAT/MINIESC.PKF', role: 'Club art, small', required: false, sha256: null, size: null, source: 'Art is out of scope for now.', confirmed: 'confirmed' },
  { id: 'oos-nanoesc', kind: 'out-of-scope', path: 'DBDAT/NANOESC.PKF', role: 'Club art, tiny', required: false, sha256: null, size: null, source: 'Art is out of scope for now.', confirmed: 'confirmed' },
  { id: 'oos-ridiesc', kind: 'out-of-scope', path: 'DBDAT/RIDIESC.PKF', role: 'Club art, ridiculous size', required: false, sha256: null, size: null, source: 'Art is out of scope for now.', confirmed: 'confirmed' },
  { id: 'oos-bigesc', kind: 'out-of-scope', path: 'DBDAT/BIGESC.PKF', role: 'Club art, large', required: false, sha256: null, size: null, source: 'Art is out of scope for now.', confirmed: 'confirmed' },
  { id: 'oos-bigcamp', kind: 'out-of-scope', path: 'DBDAT/BIGCAMP.PKF', role: 'Art (large)', required: false, sha256: null, size: null, source: 'Art is out of scope for now.', confirmed: 'confirmed' },
  { id: 'oos-bigentr', kind: 'out-of-scope', path: 'DBDAT/BIGENTR.PKF', role: 'Art (large)', required: false, sha256: null, size: null, source: 'Art is out of scope for now.', confirmed: 'confirmed' },
  { id: 'oos-miniband', kind: 'out-of-scope', path: 'DBDAT/MINIBAND.PKF', role: 'Art (small)', required: false, sha256: null, size: null, source: 'Art is out of scope for now.', confirmed: 'confirmed' },
  { id: 'oos-minientr', kind: 'out-of-scope', path: 'DBDAT/MINIENTR.PKF', role: 'Art (small)', required: false, sha256: null, size: null, source: 'Art is out of scope for now.', confirmed: 'confirmed' },
  { id: 'oos-banderas', kind: 'out-of-scope', path: 'DBDAT/BANDERAS.PKF', role: 'Flags', required: false, sha256: null, size: null, source: 'Art is out of scope for now.', confirmed: 'confirmed' },
  { id: 'oos-img', kind: 'out-of-scope', path: 'IMG.PKF', role: 'Image catalogue (root folder)', required: false, sha256: null, size: null, source: 'Images are out of scope for now.', confirmed: 'confirmed' },
  { id: 'oos-recursos', kind: 'out-of-scope', path: 'RECURSOS.PKF', role: 'Game resources (root folder)', required: false, sha256: null, size: null, source: 'Not read by the text-table patcher.', confirmed: 'confirmed' },
  { id: 'oos-rcdbase', kind: 'out-of-scope', path: 'RC_DBASE.PKF', role: 'Game resources (root folder)', required: false, sha256: null, size: null, source: 'Not read by the text-table patcher.', confirmed: 'confirmed' },
  { id: 'oos-dat', kind: 'out-of-scope', path: 'DAT.PKF', role: 'Game data (root folder)', required: false, sha256: null, size: null, source: 'Not read by the text-table patcher.', confirmed: 'confirmed' },
  { id: 'oos-musicas', kind: 'out-of-scope', path: 'Musicas.pkf', role: 'Music (root folder)', required: false, sha256: null, size: null, source: 'Audio is out of scope.', confirmed: 'confirmed' },
]);

/** Entries whose files the user is asked to capture. */
export function captureEntries(manifest = MANIFEST) {
  return manifest.filter((e) => e.kind === 'input');
}
