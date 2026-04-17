function bootMcelieceStandalonePage() {
  const links = Array.from(document.querySelectorAll('.mce-section-link[href^="#"]'));
  if (links.length === 0 || typeof IntersectionObserver === 'undefined') {
    return;
  }

  const targets = links
    .map((link) => document.querySelector(link.getAttribute('href')))
    .filter(Boolean);

  if (targets.length === 0) {
    return;
  }

  const map = new Map();
  links.forEach((link) => {
    map.set(link.getAttribute('href'), link);
  });

  const observer = new IntersectionObserver((entries) => {
    let best = null;
    for (const entry of entries) {
      if (!entry.isIntersecting) {
        continue;
      }
      if (!best || entry.intersectionRatio > best.intersectionRatio) {
        best = entry;
      }
    }
    if (!best) {
      return;
    }
    links.forEach((link) => link.classList.remove('is-active'));
    const active = map.get(`#${best.target.id}`);
    if (active) {
      active.classList.add('is-active');
    }
  }, {
    rootMargin: '-18% 0px -65% 0px',
    threshold: [0.1, 0.2, 0.4, 0.6]
  });

  targets.forEach((node) => observer.observe(node));
}

document.addEventListener('DOMContentLoaded', bootMcelieceStandalonePage);
