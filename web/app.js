'use strict';

const form = document.querySelector('form');
const input = document.querySelector('#database');
const fix = document.querySelector('#stars');
const button = document.querySelector('button');
const status = document.querySelector('#status');

input.addEventListener('change', () => { status.textContent = ''; });
form.addEventListener('submit', async event => {
  event.preventDefault();
  const file = input.files[0];
  if (!file) return;
  button.disabled = true;
  input.disabled = true;
  fix.disabled = true;
  status.textContent = 'Checking your database…';
  try {
    const { bytes, fixed } = await prepareDatabase(file, fix.checked);
    const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = 'EQ98030.FDI';
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    status.textContent = fixed
      ? 'Downloaded EQ98030.FDI with the Stars fix.'
      : 'Downloaded the original EQ98030.FDI.';
  } catch (error) {
    status.textContent = error.message;
  } finally {
    button.disabled = false;
    input.disabled = false;
    fix.disabled = false;
  }
});
