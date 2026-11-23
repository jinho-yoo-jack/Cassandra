// Browser regression probe: evaluate in the page after selecting a risk and
// settling the camera. Run at 768x1024 (detail open/closed) and 1440x960.
// No backend writes. Unlike DOM counts, hit tests detect covering panels.
(() => {
  const require = (condition, message) => { if (!condition) throw new Error(message); };
  const rect = element => element.getBoundingClientRect();
  const reachable = (element, label) => {
    require(element, `${label} is missing`);
    const bounds = rect(element);
    const hit = document.elementFromPoint(bounds.x + bounds.width / 2, bounds.y + bounds.height / 2);
    require(bounds.width > 0 && bounds.height > 0 && element.contains(hit), `${label} is covered by ${hit?.closest('aside')?.className || hit?.className || 'nothing'}`);
    return { x: bounds.x, y: bounds.y, width: bounds.width, height: bounds.height };
  };
  const selected = document.querySelector('.react-flow__node.selected');
  const navigator = document.querySelector('.graph-navigator');
  const detail = document.querySelector('.explorer-detail');
  const list = document.querySelector('.risk-list');
  const selectedBounds = reachable(selected, 'Selected node');
  const navigatorBounds = reachable(navigator, 'Navigator');
  for (const button of navigator.querySelectorAll('button:not(:disabled)')) reachable(button, button.getAttribute('aria-label') || button.textContent);
  const overlaps = (a, b) => a.x < b.x + b.width && a.x + a.width > b.x && a.y < b.y + b.height && a.y + a.height > b.y;
  require(!overlaps(selectedBounds, navigatorBounds), 'Navigator overlaps selected node');
  require(document.documentElement.scrollWidth <= window.innerWidth, 'Page overflows horizontally');
  if (window.innerWidth > 640 && window.innerWidth <= 1100) {
    require(getComputedStyle(list).display === (detail ? 'none' : 'flex'), 'Tablet risk list must return when details close');
    if (detail) {
      require(!overlaps(rect(detail), rect(document.querySelector('.explorer-map'))), 'Tablet detail must have its own layout space');
      reachable(detail.querySelector('button'), 'Detail close');
    }
  }
  return { viewport: [innerWidth, innerHeight], selectedId: selected.dataset.id, selectedBounds, navigatorBounds, detailOpen: !!detail, listDisplay: getComputedStyle(list).display, nodes: document.querySelectorAll('.react-flow__node').length };
})();
