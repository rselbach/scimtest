// Expands inspector activity rows without changing the compact table layout.
document.addEventListener('click', function (event) {
  const row = event.target.closest('[data-flow-activity-row]');
  if (!row) return;

  const disclosure = row.querySelector('[data-flow-activity-disclosure]');
  const detail = disclosure
    ? document.getElementById(disclosure.getAttribute('aria-controls'))
    : null;
  if (!disclosure || !detail) return;

  const open = disclosure.getAttribute('aria-expanded') !== 'true';
  row.classList.toggle('is-open', open);
  detail.classList.toggle('is-open', open);
  disclosure.setAttribute('aria-expanded', open ? 'true' : 'false');
  detail.setAttribute('aria-hidden', open ? 'false' : 'true');
});
