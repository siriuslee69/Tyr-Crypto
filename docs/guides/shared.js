const docPages = {
  overview: {
    title: 'Overview',
    kicker: 'Documentation Shell',
    status: 'Local HTML + MathJax',
    state: 'shared',
    path: null
  },
  kyber: {
    title: 'Kyber / ML-KEM',
    kicker: 'Performance + Security Notes',
    status: 'Implemented',
    state: 'implemented',
    path: './kyber/index.html'
  },
  dilithium: {
    title: 'Dilithium / ML-DSA',
    kicker: 'Performance + Security Notes',
    status: 'Implemented',
    state: 'implemented',
    path: './dilithium/index.html'
  },
  bike: {
    title: 'BIKE',
    kicker: 'Algorithm Notes',
    status: 'Pending',
    state: 'pending',
    path: './bike/index.html'
  },
  frodo: {
    title: 'Frodo',
    kicker: 'Performance + Security Notes',
    status: 'Implemented',
    state: 'implemented',
    path: './frodo/index.html'
  },
  mceliece: {
    title: 'Classic McEliece',
    kicker: 'Algorithm Notes',
    status: 'Implemented',
    state: 'implemented',
    path: './mceliece/index.html'
  },
  sphincs: {
    title: 'SPHINCS+',
    kicker: 'Performance + Security Notes',
    status: 'Implemented',
    state: 'implemented',
    path: './sphincs/index.html'
  }
};

let currentFilter = 'all';
let currentQuery = '';

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
        <h3>Choose an algorithm from the left menu</h3>
        <p>
          The root shell stays shared. Each algorithm keeps its own standalone HTML page under
          <code>docs/&lt;algorithm&gt;/index.html</code>. This keeps the docs book-like while the
          shell owns navigation, filtering, styling, and MathJax setup.
        </p>
      </section>
      <section class="grid-two">
        <div class="info-card">
          <h3>Ready</h3>
          <ul>
            <li>Kyber / ML-KEM</li>
            <li>Dilithium / ML-DSA</li>
            <li>Frodo</li>
            <li>Classic McEliece</li>
            <li>SPHINCS+</li>
          </ul>
        </div>
        <div class="info-card">
          <h3>Pending</h3>
          <ul>
            <li>BIKE</li>
          </ul>
        </div>
      </section>
      <section class="placeholder">
        <p>
          Use the search field and the <strong>Ready</strong> / <strong>Pending</strong> filters in
          the left rail to move through the current writeups.
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

function setPageMeta(slug, overrideTitle = '') {
  const meta = docPages[slug] || docPages.overview;
  const title = overrideTitle || meta.title;
  document.title = title === 'Overview'
    ? 'Tyr-Crypto Algorithm Notes'
    : `${title} | Tyr-Crypto Algorithm Notes`;
}

function setFilterState() {
  const nodes = document.querySelectorAll('.filter-link');
  nodes.forEach((node) => {
    node.classList.toggle('is-active', node.dataset.filter === currentFilter);
  });
}

function shouldShowPage(slug, meta, activeSlug) {
  if (slug === activeSlug) {
    return true;
  }

  const query = currentQuery.trim().toLowerCase();
  const queryText = `${slug} ${meta.title} ${meta.kicker}`.toLowerCase();
  const queryMatch = query.length === 0 || queryText.includes(query);

  if (slug === 'overview') {
    return queryMatch;
  }

  const filterMatch = currentFilter === 'all' || meta.state === currentFilter;
  return queryMatch && filterMatch;
}

function applyNavState() {
  const links = document.querySelectorAll('.nav-link');
  const activeSlug = routeFromHash();

  links.forEach((node) => {
    const slug = node.dataset.page || 'overview';
    const meta = docPages[slug] || docPages.overview;
    const visible = shouldShowPage(slug, meta, activeSlug);
    node.hidden = !visible;
  });

  setFilterState();
}

async function loadPage(slug) {
  const meta = docPages[slug] || docPages.overview;
  const root = document.getElementById('doc-content');

  setActive(slug);
  setPageMeta(slug);
  applyNavState();

  if (!meta.path) {
    root.innerHTML = overviewMarkup();
    return;
  }

  if (window.location.protocol === 'file:' && meta.state === 'implemented') {
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
    const bodyTitle = doc.body ? doc.body.dataset.docTitle || '' : '';
    root.innerHTML = bodyHtml;
    setPageMeta(slug, bodyTitle);

    if (window.MathJax && window.MathJax.typesetPromise) {
      await window.MathJax.typesetPromise([root]);
    }
  } catch (_error) {
    root.innerHTML = placeholderMarkup(slug);
    setPageMeta(slug);
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
  const filterLinks = document.querySelectorAll('.filter-link');
  const searchInput = document.getElementById('doc-search');
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

  filterLinks.forEach((node) => {
    node.addEventListener('click', () => {
      currentFilter = node.dataset.filter || 'all';
      applyNavState();
    });
  });

  if (searchInput) {
    searchInput.addEventListener('input', () => {
      currentQuery = searchInput.value || '';
      applyNavState();
    });
  }

  window.addEventListener('hashchange', () => {
    loadPage(routeFromHash());
  });

  applyNavState();
  loadPage(routeFromHash());
}

document.addEventListener('DOMContentLoaded', bootDocsShell);
