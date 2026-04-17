const docPages = {
  overview: {
    title: 'Overview',
    kicker: 'Documentation Shell',
    status: 'Local HTML + MathJax',
    path: null
  },
  kyber: {
    title: 'Kyber / ML-KEM',
    kicker: 'Performance + Security Notes',
    status: 'Implemented',
    path: './kyber/index.html'
  },
  dilithium: {
    title: 'Dilithium / ML-DSA',
    kicker: 'Performance + Security Notes',
    status: 'Implemented',
    path: './dilithium/index.html'
  },
  bike: {
    title: 'BIKE',
    kicker: 'Algorithm Notes',
    status: 'Pending',
    path: './bike/index.html'
  },
  frodo: {
    title: 'Frodo',
    kicker: 'Performance + Security Notes',
    status: 'Implemented',
    path: './frodo/index.html'
  },
  mceliece: {
    title: 'Classic McEliece',
    kicker: 'Algorithm Notes',
    status: 'Pending',
    path: './mceliece/index.html'
  },
  sphincs: {
    title: 'SPHINCS+',
    kicker: 'Performance + Security Notes',
    status: 'Implemented',
    path: './sphincs/index.html'
  }
};

function iframeMarkup(meta) {
  return `
    <iframe
      class="doc-frame"
      src="${meta.path}"
      title="${meta.title}"
      loading="lazy"
      referrerpolicy="no-referrer"
    ></iframe>
  `;
}

function overviewMarkup() {
  return `
    <article class="doc-page">
      <section class="hero-card">
        <p class="eyebrow">Documentation Shell</p>
        <h3>Choose an algorithm from the left rail</h3>
        <p>
          The root shell stays shared. Each algorithm keeps its own standalone HTML page under
          <code>docs/&lt;algorithm&gt;/index.html</code>. This lets different contributors extend the notes
          without touching the loader, styling, or MathJax setup.
        </p>
      </section>
      <section class="placeholder">
        <p>
          The current authored pages are <strong>Kyber / ML-KEM</strong> and
          <strong>Dilithium / ML-DSA</strong> and <strong>Frodo</strong> and <strong>SPHINCS+</strong>. The remaining folders are wired into the loader and will
          show a placeholder until their pages exist.
        </p>
      </section>
    </article>
  `;
}

function placeholderMarkup(slug) {
  const meta = docPages[slug];
  return `
    <article class="doc-page">
      <section class="hero-card">
        <p class="eyebrow">${meta.kicker}</p>
        <h3>${meta.title}</h3>
        <p>This page has not been written yet.</p>
      </section>
      <section class="placeholder">
        <p>
          Add <code>docs/${slug}/index.html</code> and the shell will load it automatically.
        </p>
      </section>
    </article>
  `;
}

function setActive(slug) {
  const links = document.querySelectorAll('.nav-link');
  links.forEach((node) => {
    node.classList.toggle('is-active', node.dataset.page === slug);
  });
}

function setHeader(slug) {
  const meta = docPages[slug] || docPages.overview;
  document.getElementById('page-title').textContent = meta.title;
  document.getElementById('page-kicker').textContent = meta.kicker;
  document.getElementById('page-status').textContent = meta.status;
}

async function loadPage(slug) {
  const meta = docPages[slug] || docPages.overview;
  const root = document.getElementById('doc-content');

  setActive(slug);
  setHeader(slug);

  if (!meta.path) {
    root.innerHTML = overviewMarkup();
    return;
  }

  if (window.location.protocol === 'file:' && meta.status === 'Implemented') {
    root.innerHTML = iframeMarkup(meta);
    return;
  }

  try {
    const response = await fetch(meta.path);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const html = await response.text();
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, 'text/html');
    const bodyHtml = doc.body ? doc.body.innerHTML : html;
    const bodyTitle = doc.body ? doc.body.dataset.docTitle : '';
    const bodyKicker = doc.body ? doc.body.dataset.docKicker : '';
    root.innerHTML = bodyHtml;

    if (bodyTitle) {
      document.getElementById('page-title').textContent = bodyTitle;
    }
    if (bodyKicker) {
      document.getElementById('page-kicker').textContent = bodyKicker;
    }

    if (window.MathJax && window.MathJax.typesetPromise) {
      await window.MathJax.typesetPromise([root]);
    }
  } catch (_error) {
    root.innerHTML = placeholderMarkup(slug);
  }
}

function routeFromHash() {
  const slug = window.location.hash.replace(/^#/, '').trim();
  if (!slug || !docPages[slug]) {
    return 'overview';
  }
  return slug;
}

function bootDocsShell() {
  const links = document.querySelectorAll('.nav-link');
  const root = document.getElementById('doc-content');

  root.addEventListener('click', (event) => {
    const link = event.target.closest('a[href^="#"]');
    if (!link) {
      return;
    }

    const targetId = (link.getAttribute('href') || '').slice(1);
    const target = document.getElementById(targetId);

    if (!target || !root.contains(target)) {
      return;
    }

    event.preventDefault();
    target.scrollIntoView({
      behavior: 'smooth',
      block: 'start'
    });
  });

  links.forEach((node) => {
    node.addEventListener('click', () => {
      const slug = node.dataset.page || 'overview';
      if (window.location.hash !== `#${slug}`) {
        window.location.hash = slug;
        return;
      }
      loadPage(slug);
    });
  });

  window.addEventListener('hashchange', () => {
    loadPage(routeFromHash());
  });

  loadPage(routeFromHash());
}

document.addEventListener('DOMContentLoaded', bootDocsShell);
