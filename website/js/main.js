/**
 * ANSARK — Global Site JavaScript
 * Handles: nav scroll, mobile menu, scroll animations, mouse glow, form
 */

// ── Navigation Scroll Effect ─────────────────────────────────────────────────
const nav = document.querySelector('.nav');
const navToggle = document.querySelector('.nav-toggle');
const navMobile = document.querySelector('.nav-mobile');

let lastScroll = 0;

function handleNavScroll() {
  const scrollY = window.scrollY;
  if (scrollY > 40) {
    nav?.classList.add('scrolled');
  } else {
    nav?.classList.remove('scrolled');
  }
  lastScroll = scrollY;
}

window.addEventListener('scroll', handleNavScroll, { passive: true });
handleNavScroll();

// ── Mobile Menu Toggle ───────────────────────────────────────────────────────
navToggle?.addEventListener('click', () => {
  navToggle.classList.toggle('active');
  navMobile?.classList.toggle('open');
  document.body.style.overflow = navMobile?.classList.contains('open') ? 'hidden' : '';
});

// Close mobile menu on link click
navMobile?.querySelectorAll('.nav-link').forEach(link => {
  link.addEventListener('click', () => {
    navToggle?.classList.remove('active');
    navMobile?.classList.remove('open');
    document.body.style.overflow = '';
  });
});

// ── Scroll Reveal Animations ─────────────────────────────────────────────────
const observerOptions = {
  threshold: 0.1,
  rootMargin: '0px 0px -60px 0px',
};

const revealObserver = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.classList.add('visible');
      revealObserver.unobserve(entry.target);
    }
  });
}, observerOptions);

document.querySelectorAll('.animate-in, .stagger-children').forEach(el => {
  revealObserver.observe(el);
});

// ── Card Mouse Glow Effect ───────────────────────────────────────────────────
document.querySelectorAll('.card').forEach(card => {
  card.addEventListener('mousemove', (e) => {
    const rect = card.getBoundingClientRect();
    const x = ((e.clientX - rect.left) / rect.width) * 100;
    const y = ((e.clientY - rect.top) / rect.height) * 100;
    card.style.setProperty('--mouse-x', `${x}%`);
    card.style.setProperty('--mouse-y', `${y}%`);
  });
});

// ── Smooth Scroll for Anchor Links ───────────────────────────────────────────
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
  anchor.addEventListener('click', (e) => {
    const target = document.querySelector(anchor.getAttribute('href'));
    if (target) {
      e.preventDefault();
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });
});

// ── Active Nav Link ──────────────────────────────────────────────────────────
const currentPath = window.location.pathname.replace(/\/$/, '') || '/';
document.querySelectorAll('.nav-link').forEach(link => {
  const href = link.getAttribute('href')?.replace(/\/$/, '') || '/';
  const linkPath = href.startsWith('/') ? href : `/${href}`;
  if (linkPath === currentPath || (currentPath.endsWith('.html') && linkPath === currentPath.replace('.html', ''))) {
    link.classList.add('active');
  }
  // Also match .html versions
  if (currentPath === '/' && (href === '/' || href === '/index.html' || href === 'index.html')) {
    link.classList.add('active');
  }
});

// ── Counter Animation ────────────────────────────────────────────────────────
function animateCounters() {
  document.querySelectorAll('[data-counter]').forEach(el => {
    const target = parseInt(el.dataset.counter, 10);
    const suffix = el.dataset.suffix || '';
    const duration = 1500;
    const start = performance.now();

    function update(now) {
      const elapsed = now - start;
      const progress = Math.min(elapsed / duration, 1);
      // Ease out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      const current = Math.round(target * eased);
      el.textContent = current + suffix;
      if (progress < 1) {
        requestAnimationFrame(update);
      }
    }

    requestAnimationFrame(update);
  });
}

// Trigger counter animation when stats section is visible
const statsSection = document.querySelector('.stats-section');
if (statsSection) {
  const statsObserver = new IntersectionObserver((entries) => {
    if (entries[0].isIntersecting) {
      animateCounters();
      statsObserver.disconnect();
    }
  }, { threshold: 0.3 });
  statsObserver.observe(statsSection);
}

// ── Contact Form Handling ────────────────────────────────────────────────────
const contactForm = document.getElementById('contact-form');
contactForm?.addEventListener('submit', async (e) => {
  e.preventDefault();
  
  const btn = contactForm.querySelector('.btn-primary');
  const originalText = btn.textContent;
  btn.textContent = 'SENDING...';
  btn.disabled = true;

  // Collect form data
  const formData = new FormData(contactForm);
  const data = Object.fromEntries(formData.entries());

  // In production, POST to your backend or Formspree endpoint
  // For now, simulate success
  await new Promise(resolve => setTimeout(resolve, 1200));

  btn.textContent = '✓ SENT SUCCESSFULLY';
  btn.style.background = 'var(--gradient-accent)';
  
  setTimeout(() => {
    btn.textContent = originalText;
    btn.disabled = false;
    btn.style.background = '';
    contactForm.reset();
  }, 3000);
});

// ── YAML Typing Animation (Hero) ─────────────────────────────────────────────
function typeYamlLine(element, text, delay = 0) {
  return new Promise(resolve => {
    setTimeout(() => {
      let i = 0;
      element.textContent = '';
      element.style.visibility = 'visible';
      
      function type() {
        if (i < text.length) {
          element.textContent += text[i];
          i++;
          requestAnimationFrame(() => setTimeout(type, 12));
        } else {
          resolve();
        }
      }
      type();
    }, delay);
  });
}

// Run YAML animation if hero terminal exists
const heroTerminal = document.querySelector('.hero-terminal-body');
if (heroTerminal) {
  const lines = heroTerminal.querySelectorAll('.yaml-line');
  lines.forEach(line => {
    line.dataset.text = line.textContent;
    line.textContent = '';
    line.style.visibility = 'hidden';
  });

  let delay = 500;
  lines.forEach((line, i) => {
    typeYamlLine(line, line.dataset.text, delay);
    delay += Math.max(100, line.dataset.text.length * 8);
  });
}

// ── Performance: Preload critical resources ──────────────────────────────────
if ('connection' in navigator) {
  const conn = navigator.connection;
  if (conn && !conn.saveData && conn.effectiveType !== '2g') {
    // Prefetch other pages on fast connections
    ['product', 'solutions', 'architecture', 'security', 'contact'].forEach(page => {
      const link = document.createElement('link');
      link.rel = 'prefetch';
      link.href = `/${page}.html`;
      document.head.appendChild(link);
    });
  }
}
