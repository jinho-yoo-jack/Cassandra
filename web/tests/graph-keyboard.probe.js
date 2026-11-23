// Browser regression probe: evaluate immediately after Enter selects a risk.
// A responsive layout may hide the risk list; focus must enter the new details.
(() => {
  const detail = document.querySelector('.explorer-detail');
  const focused = document.activeElement;
  if (!detail || !detail.contains(focused)) throw new Error('Keyboard focus did not enter the opened details');
  const bounds = focused.getBoundingClientRect();
  if (!bounds.width || !bounds.height || bounds.top < 0 || bounds.bottom > innerHeight)
    throw new Error('Opened-detail keyboard focus is not visible');
  return { role: focused.tagName, label: focused.getAttribute('aria-label'), visible: true };
})();
