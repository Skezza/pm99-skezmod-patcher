import { type FormEvent, useState } from 'react';
import { prepareDatabase } from './lib/starsDatabase';

export function StarsDatabase() {
  const [file, setFile] = useState<File>();
  const [applyFix, setApplyFix] = useState(true);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState('');

  async function download(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!file || busy) return;
    setBusy(true);
    setStatus('Checking your database…');
    try {
      const { bytes, fixed } = await prepareDatabase(file, applyFix);
      const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
      const link = document.createElement('a');
      link.href = url;
      link.download = 'EQ98030.FDI';
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      setStatus(fixed ? 'Downloaded EQ98030.FDI with the Stars fix.' : 'Downloaded your database unchanged.');
    } catch (error) {
      setStatus(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="panel" onSubmit={download}>
      <h2>Club database</h2>
      <p><label htmlFor="club-database">Choose DBDAT/EQ98030.FDI from your English retail game.</label></p>
      <input
        id="club-database"
        type="file"
        accept=".fdi"
        disabled={busy}
        onChange={event => {
          setFile(event.currentTarget.files?.[0]);
          setStatus('');
        }}
      />
      <div className="option-list">
        <label title="Moves the Stars club record from database ID 9900 to 9899.">
          <input type="checkbox" checked={applyFix} disabled={busy} onChange={event => setApplyFix(event.currentTarget.checked)} />
          <span>Fix the Stars player crash</span>
        </label>
        <details>
          <summary>How the fix works</summary>
          <p>Moves Stars from club ID 9900 to 9899 so the game displays the club name normally. The roster and executable stay untouched.</p>
        </details>
      </div>
      <button type="submit" className="primary" disabled={!file || busy}>Download club database</button>
      <p>Back up the original before replacing it in your game’s DBDAT folder.</p>
      {status && <p className="status-line" role="status">{status}</p>}
    </form>
  );
}
