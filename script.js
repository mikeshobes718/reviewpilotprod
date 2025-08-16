'use strict';

// Data source for the landing page content
const siteData = {
  "businessName": "Mama's Nigerian Kitchen",
  "logoUrl": "https://placehold.co/150x50/png?text=Mama's+Kitchen",
  "hero": {
    "headline": "Authentic Nigerian Flavors, Delivered to Your Doorstep",
    "subheadline": "Experience the taste of home with our freshly prepared meals.",
    "ctaText": "View Menu & Order Now",
    "backgroundImageUrl": "https://placehold.co/1920x1080/jpeg?text=Delicious+Jollof+Rice"
  },
  "popularDishes": [
    {
      "name": "Jollof Rice with Chicken",
      "description": "Our signature smoky party jollof rice served with succulent grilled chicken.",
      "imageUrl": "https://placehold.co/600x400/jpeg?text=Jollof+Rice"
    },
    {
      "name": "Egusi Soup with Pounded Yam",
      "description": "A rich and hearty soup made with ground melon seeds, fresh vegetables, and assorted meat.",
      "imageUrl": "https://placehold.co/600x400/jpeg?text=Egusi+Soup"
    },
    {
      "name": "Suya (Spicy Grilled Skewers)",
      "description": "Tender beef skewers marinated in a spicy peanut blend and grilled to perfection.",
      "imageUrl": "https://placehold.co/600x400/jpeg?text=Suya"
    }
  ],
  // Menu content will be attached below to keep this section readable
  "howItWorks": [
    {
      "step": 1,
      "title": "Browse Our Menu",
      "description": "Explore our wide range of authentic Nigerian dishes."
    },
    {
      "step": 2,
      "title": "Place Your Order",
      "description": "Select your favorite meals and pay securely online."
    },
    {
      "step": 3,
      "title": "Enjoy Your Meal",
      "description": "Get your food delivered hot and fresh to your doorstep."
    }
  ],
  "contact": {
    "phone": "+234-812-345-6789",
    "email": "orders@mamaskitchen.com",
    "social": {
      "instagram": "https://instagram.com/mamaskitchen",
      "facebook": "https://facebook.com/mamaskitchen"
    }
  }
};

document.addEventListener('DOMContentLoaded', () => {
  populatePage(siteData);
  setupInteractions();
  if (isMenuPage()) {
    buildMenuPage(siteData);
  }
  initCart();
});

function populatePage(data) {
  // Document title
  document.title = `${data.businessName} — Authentic Nigerian Food Delivered`;

  // Logos
  const logoImg = document.getElementById('logo');
  const footerLogoImg = document.getElementById('footer-logo');
  if (logoImg) {
    logoImg.src = data.logoUrl;
    logoImg.alt = `${data.businessName} logo`;
  }
  if (footerLogoImg) {
    footerLogoImg.src = data.logoUrl;
    footerLogoImg.alt = `${data.businessName} logo`;
  }

  // Hero
  const heroSection = document.querySelector('.hero');
  const heroHeadline = document.getElementById('hero-headline');
  const heroSubheadline = document.getElementById('hero-subheadline');
  const heroCta = document.getElementById('hero-cta');

  if (heroSection) {
    heroSection.style.backgroundImage = `url('${data.hero.backgroundImageUrl}')`;
  }
  if (heroHeadline) heroHeadline.textContent = data.hero.headline;
  if (heroSubheadline) heroSubheadline.textContent = data.hero.subheadline;
  if (heroCta) {
    heroCta.textContent = data.hero.ctaText;
    heroCta.setAttribute('href', '#popular-dishes');
  }

  // Popular Dishes
  const dishesGrid = document.getElementById('dishes-grid');
  if (dishesGrid && Array.isArray(data.popularDishes)) {
    data.popularDishes.forEach((dish) => {
      const card = document.createElement('article');
      card.className = 'dish-card';

      const media = document.createElement('div');
      media.className = 'dish-media';
      const img = document.createElement('img');
      img.src = dish.imageUrl;
      img.alt = dish.name;
      img.loading = 'lazy';
      media.appendChild(img);

      const body = document.createElement('div');
      body.className = 'dish-body';

      const title = document.createElement('h3');
      title.className = 'dish-title';
      title.textContent = dish.name;

      const desc = document.createElement('p');
      desc.className = 'dish-desc';
      desc.textContent = dish.description;

      body.appendChild(title);
      body.appendChild(desc);

      card.appendChild(media);
      card.appendChild(body);
      dishesGrid.appendChild(card);
    });
  }

  // How It Works
  const stepsGrid = document.getElementById('steps');
  if (stepsGrid && Array.isArray(data.howItWorks)) {
    data.howItWorks.forEach((step) => {
      const item = document.createElement('div');
      item.className = 'step-card';

      const num = document.createElement('div');
      num.className = 'step-num';
      num.textContent = String(step.step);

      const title = document.createElement('h3');
      title.className = 'step-title';
      title.textContent = step.title;

      const desc = document.createElement('p');
      desc.className = 'step-desc';
      desc.textContent = step.description;

      item.appendChild(num);
      item.appendChild(title);
      item.appendChild(desc);
      stepsGrid.appendChild(item);
    });
  }

  // Footer — Contact and Social
  const phoneLink = document.getElementById('contact-phone');
  const emailLink = document.getElementById('contact-email');
  const igLink = document.getElementById('instagram-link');
  const fbLink = document.getElementById('facebook-link');
  const tagline = document.getElementById('footer-tagline');

  if (phoneLink) {
    phoneLink.href = `tel:${data.contact.phone.replace(/\s+/g, '')}`;
    phoneLink.textContent = data.contact.phone;
  }
  if (emailLink) {
    emailLink.href = `mailto:${data.contact.email}`;
    emailLink.textContent = data.contact.email;
  }
  if (igLink) {
    igLink.href = data.contact.social.instagram;
  }
  if (fbLink) {
    fbLink.href = data.contact.social.facebook;
  }
  if (tagline) {
    tagline.textContent = 'Authentic Nigerian flavors, made with love.';
  }

  const copyright = document.getElementById('copyright');
  if (copyright) {
    const year = new Date().getFullYear();
    copyright.textContent = `© ${year} ${data.businessName}. All rights reserved.`;
  }
}

function setupInteractions() {
  // Mobile nav toggle
  const navToggle = document.getElementById('nav-toggle');
  const navMenu = document.getElementById('nav-menu');
  if (navToggle && navMenu) {
    navToggle.addEventListener('click', () => {
      const isOpen = navMenu.classList.toggle('is-open');
      navToggle.setAttribute('aria-expanded', String(isOpen));
    });

    // Close menu after clicking a link (on mobile)
    navMenu.querySelectorAll('a').forEach((link) => {
      link.addEventListener('click', () => {
        if (navMenu.classList.contains('is-open')) {
          navMenu.classList.remove('is-open');
          navToggle.setAttribute('aria-expanded', 'false');
        }
      });
    });
  }

  // Header shadow on scroll
  const header = document.querySelector('.site-header');
  const onScroll = () => {
    if (!header) return;
    if (window.scrollY > 8) header.classList.add('scrolled');
    else header.classList.remove('scrolled');
  };
  onScroll();
  window.addEventListener('scroll', onScroll, { passive: true });
}

// ------- Menu Page Logic ------- //

// Attach full menu data
siteData.menu = {
  pageTitle: 'Our Full Menu',
  categories: [
    {
      name: 'Soups & Stews',
      items: [
        {
          id: 'S01',
          name: 'Egusi Soup',
          description: 'A rich soup made from melon seeds, spinach, and assorted meats.',
          price: 4500,
          imageUrl: 'https://placehold.co/600x400/jpeg?text=Egusi'
        },
        {
          id: 'S02',
          name: 'Efo Riro',
          description: 'A flavorful Yoruba vegetable soup with locust beans and bell peppers.',
          price: 4000,
          imageUrl: 'https://placehold.co/600x400/jpeg?text=Efo+Riro'
        },
        {
          id: 'S03',
          name: 'Afang Soup',
          description: 'A hearty vegetable soup from the Efik people, rich in protein and flavor.',
          price: 5000,
          imageUrl: 'https://placehold.co/600x400/jpeg?text=Afang+Soup'
        }
      ]
    },
    {
      name: 'Rice Dishes',
      items: [
        {
          id: 'R01',
          name: 'Jollof Rice',
          description: 'Smoky, long-grain rice cooked in a savory tomato and pepper sauce.',
          price: 3500,
          imageUrl: 'https://placehold.co/600x400/jpeg?text=Jollof+Rice'
        },
        {
          id: 'R02',
          name: 'Fried Rice',
          description: 'Classic Nigerian fried rice with mixed vegetables, liver, and shrimp.',
          price: 3500,
          imageUrl: 'https://placehold.co/600x400/jpeg?text=Fried+Rice'
        },
        {
          id: 'R03',
          name: 'Ofada Rice & Stew',
          description: 'Local unpolished rice served with a spicy, bleached palm oil stew.',
          price: 5500,
          imageUrl: 'https://placehold.co/600x400/jpeg?text=Ofada+Rice'
        }
      ]
    },
    {
      name: 'Swallows & Sides',
      items: [
        {
          id: 'SW01',
          name: 'Pounded Yam',
          description: 'A smooth, dough-like swallow made from boiled yams.',
          price: 1000,
          imageUrl: 'https://placehold.co/600x400/jpeg?text=Pounded+Yam'
        },
        {
          id: 'SW02',
          name: 'Amala',
          description: 'Made from yam flour, with a distinctive dark color and light texture.',
          price: 1000,
          imageUrl: 'https://placehold.co/600x400/jpeg?text=Amala'
        },
        {
          id: 'SD01',
          name: 'Fried Plantain (Dodo)',
          description: 'Sweet, ripe plantains, deep-fried to golden perfection.',
          price: 1500,
          imageUrl: 'https://placehold.co/600x400/jpeg?text=Dodo'
        }
      ]
    }
  ]
};

function isMenuPage() {
  return (
    (document.body && document.body.dataset && document.body.dataset.page === 'menu') ||
    !!document.getElementById('menu-categories')
  );
}

function buildMenuPage(data) {
  if (!data || !data.menu) return;
  const { menu } = data;

  // Title
  const menuTitle = document.getElementById('menu-title');
  if (menuTitle) menuTitle.textContent = menu.pageTitle || 'Menu';

  const container = document.getElementById('menu-categories');
  if (!container) return;

  menu.categories.forEach((category) => {
    const section = document.createElement('section');
    section.className = 'menu-category';

    const heading = document.createElement('h2');
    heading.className = 'menu-category-title';
    heading.textContent = category.name;

    const grid = document.createElement('div');
    grid.className = 'grid menu-grid';

    category.items.forEach((item) => {
      const card = document.createElement('article');
      card.className = 'menu-card';
      card.setAttribute('data-id', item.id);

      const media = document.createElement('div');
      media.className = 'menu-media';
      const img = document.createElement('img');
      img.src = item.imageUrl;
      img.alt = item.name;
      img.loading = 'lazy';
      media.appendChild(img);

      const body = document.createElement('div');
      body.className = 'menu-body';

      const title = document.createElement('h3');
      title.className = 'menu-title';
      title.textContent = item.name;

      const desc = document.createElement('p');
      desc.className = 'menu-desc';
      desc.textContent = item.description;

      const meta = document.createElement('div');
      meta.className = 'menu-meta';

      const price = document.createElement('span');
      price.className = 'price';
      price.textContent = formatNaira(item.price);

      const btn = document.createElement('button');
      btn.className = 'btn btn-outline btn-sm';
      btn.type = 'button';
      btn.textContent = 'Add to Order';
      btn.addEventListener('click', () => {
        // Placeholder action for future cart integration
        // eslint-disable-next-line no-console
        console.log('Add to Order:', { id: item.id, name: item.name, price: item.price });
        btn.textContent = 'Added!';
        btn.disabled = true;
        setTimeout(() => {
          btn.textContent = 'Add to Order';
          btn.disabled = false;
        }, 1000);
      });

      meta.appendChild(price);
      meta.appendChild(btn);

      body.appendChild(title);
      body.appendChild(desc);
      body.appendChild(meta);

      card.appendChild(media);
      card.appendChild(body);
      grid.appendChild(card);
    });

    section.appendChild(heading);
    section.appendChild(grid);
    container.appendChild(section);
  });
}

function formatNaira(amount) {
  try {
    return new Intl.NumberFormat('en-NG', {
      style: 'currency',
      currency: 'NGN',
      minimumFractionDigits: 0,
      maximumFractionDigits: 0
    }).format(amount);
  } catch (_) {
    return `₦${Number(amount).toLocaleString('en-NG')}`;
  }
}

// ------------- CART ------------- //

const cartState = {
  items: [] // { id: string, quantity: number }
};

function initCart() {
  // Restore cart from localStorage
  try {
    const stored = localStorage.getItem('mk_cart');
    if (stored) {
      const parsed = JSON.parse(stored);
      if (Array.isArray(parsed)) cartState.items = parsed;
    }
  } catch (_) {}

  // Cache DOM
  const cartButton = document.getElementById('cart-button');
  const cartBadge = document.getElementById('cart-badge');
  const cartDrawer = document.getElementById('cart-drawer');
  const cartOverlay = document.getElementById('cart-overlay');
  const cartClose = document.getElementById('cart-close');
  const checkoutButton = document.getElementById('checkout-button');

  // Toggle handlers
  const openCart = () => {
    if (!cartDrawer || !cartOverlay) return;
    cartDrawer.classList.add('is-open');
    cartOverlay.classList.add('is-open');
    cartDrawer.setAttribute('aria-hidden', 'false');
    if (cartButton) cartButton.setAttribute('aria-expanded', 'true');
  };
  const closeCart = () => {
    if (!cartDrawer || !cartOverlay) return;
    cartDrawer.classList.remove('is-open');
    cartOverlay.classList.remove('is-open');
    cartDrawer.setAttribute('aria-hidden', 'true');
    if (cartButton) cartButton.setAttribute('aria-expanded', 'false');
  };
  const toggleCart = () => {
    if (!cartDrawer) return;
    if (cartDrawer.classList.contains('is-open')) closeCart();
    else openCart();
  };

  // Event listeners
  if (cartButton) cartButton.addEventListener('click', toggleCart);
  if (cartOverlay) cartOverlay.addEventListener('click', closeCart);
  if (cartClose) cartClose.addEventListener('click', closeCart);
  if (checkoutButton) {
    checkoutButton.addEventListener('click', () => {
      window.location.href = 'checkout.html';
    });
  }

  // Delegate Add to Order clicks
  document.body.addEventListener('click', (e) => {
    const target = e.target;
    if (!(target instanceof HTMLElement)) return;
    if (target.matches('.btn') && /add to order/i.test(target.textContent || '')) {
      const card = target.closest('[data-id]');
      if (!card) return;
      const itemId = card.getAttribute('data-id');
      if (itemId) addToCart(itemId, target);
    }
  });

  // Initial render
  updateCartDisplay();
  animateBadge(cartBadge); // subtle entrance if items exist
}

function saveCart() {
  try {
    localStorage.setItem('mk_cart', JSON.stringify(cartState.items));
  } catch (_) {}
}

function addToCart(itemId, sourceButton) {
  const existing = cartState.items.find((it) => it.id === itemId);
  if (existing) existing.quantity += 1;
  else cartState.items.push({ id: itemId, quantity: 1 });
  saveCart();
  updateCartDisplay();
  // Visual feedback
  if (sourceButton) {
    sourceButton.disabled = true;
    sourceButton.textContent = 'Added!';
    setTimeout(() => {
      sourceButton.disabled = false;
      sourceButton.textContent = 'Add to Order';
    }, 900);
  }
  const cartButton = document.getElementById('cart-button');
  if (cartButton) bounce(cartButton);
}

function removeFromCart(itemId) {
  cartState.items = cartState.items.filter((it) => it.id !== itemId);
  saveCart();
  updateCartDisplay();
}

function incrementQty(itemId) {
  const it = cartState.items.find((i) => i.id === itemId);
  if (it) it.quantity += 1;
  saveCart();
  updateCartDisplay();
}

function decrementQty(itemId) {
  const it = cartState.items.find((i) => i.id === itemId);
  if (!it) return;
  it.quantity -= 1;
  if (it.quantity <= 0) {
    removeFromCart(itemId);
  } else {
    saveCart();
    updateCartDisplay();
  }
}

function getCartDetailedItems() {
  const catalog = buildCatalogIndex(siteData);
  return cartState.items
    .map((ci) => ({ ...ci, detail: catalog[ci.id] }))
    .filter((ci) => ci.detail);
}

function buildCatalogIndex(data) {
  const index = {};
  // Include menu items
  if (data.menu && Array.isArray(data.menu.categories)) {
    data.menu.categories.forEach((cat) => {
      cat.items.forEach((it) => {
        index[it.id] = it;
      });
    });
  }
  // Map popular dishes too (assign synthetic ids if missing)
  if (Array.isArray(data.popularDishes)) {
    data.popularDishes.forEach((dish, idx) => {
      const id = dish.id || `P${String(idx + 1).padStart(2, '0')}`;
      index[id] = { id, name: dish.name, description: dish.description, price: dish.price || 0, imageUrl: dish.imageUrl };
    });
  }
  return index;
}

function updateCartDisplay() {
  const cartItemsEl = document.getElementById('cart-items');
  const subtotalEl = document.getElementById('cart-subtotal');
  const badgeEl = document.getElementById('cart-badge');
  if (!cartItemsEl || !subtotalEl || !badgeEl) return;

  cartItemsEl.innerHTML = '';
  const detailed = getCartDetailedItems();

  let subtotal = 0;
  detailed.forEach((ci) => {
    const { id, quantity, detail } = ci;
    const linePrice = (detail.price || 0) * quantity;
    subtotal += linePrice;

    const row = document.createElement('div');
    row.className = 'cart-item';

    const img = document.createElement('img');
    img.src = detail.imageUrl;
    img.alt = detail.name;
    img.loading = 'lazy';

    const info = document.createElement('div');
    const title = document.createElement('p');
    title.className = 'cart-item-title';
    title.textContent = detail.name;
    const desc = document.createElement('p');
    desc.className = 'cart-item-desc';
    desc.textContent = detail.description || '';

    const qty = document.createElement('div');
    qty.className = 'cart-qty';
    const minus = document.createElement('button');
    minus.className = 'qty-btn';
    minus.type = 'button';
    minus.textContent = '−';
    minus.addEventListener('click', () => decrementQty(id));
    const val = document.createElement('span');
    val.className = 'qty-value';
    val.textContent = String(quantity);
    const plus = document.createElement('button');
    plus.className = 'qty-btn';
    plus.type = 'button';
    plus.textContent = '+';
    plus.addEventListener('click', () => incrementQty(id));
    qty.appendChild(minus);
    qty.appendChild(val);
    qty.appendChild(plus);

    info.appendChild(title);
    info.appendChild(desc);
    info.appendChild(qty);

    const actions = document.createElement('div');
    actions.className = 'cart-item-actions';
    const line = document.createElement('div');
    line.className = 'cart-item-price';
    line.textContent = formatNaira(linePrice);
    const remove = document.createElement('button');
    remove.className = 'remove-btn';
    remove.type = 'button';
    remove.textContent = 'Remove';
    remove.addEventListener('click', () => removeFromCart(id));

    actions.appendChild(line);
    actions.appendChild(remove);

    row.appendChild(img);
    row.appendChild(info);
    row.appendChild(actions);
    cartItemsEl.appendChild(row);
  });

  subtotalEl.textContent = formatNaira(subtotal);

  const totalItems = cartState.items.reduce((acc, it) => acc + it.quantity, 0);
  badgeEl.textContent = String(totalItems);
  if (totalItems > 0) badgeEl.hidden = false; else badgeEl.hidden = true;
}

function bounce(element) {
  if (!element) return;
  element.animate(
    [
      { transform: 'translateY(0)' },
      { transform: 'translateY(-4px)' },
      { transform: 'translateY(0)' }
    ],
    { duration: 220, easing: 'ease-out' }
  );
}

function animateBadge(badge) {
  if (!badge || badge.hidden) return;
  badge.animate(
    [
      { transform: 'scale(0.8)', opacity: 0.6 },
      { transform: 'scale(1.1)', opacity: 1 },
      { transform: 'scale(1)', opacity: 1 }
    ],
    { duration: 220, easing: 'ease-out' }
  );
}

// --------- Checkout Page --------- //
document.addEventListener('DOMContentLoaded', () => {
  if (isCheckoutPage()) {
    displayCheckoutPage();
    setupProceedHandler();
  }
});

function isCheckoutPage() {
  return (document.body && document.body.dataset && document.body.dataset.page === 'checkout');
}

function displayCheckoutPage() {
  const itemsWrap = document.getElementById('checkout-items');
  const subtotalEl = document.getElementById('summary-subtotal');
  const deliveryEl = document.getElementById('summary-delivery');
  const totalEl = document.getElementById('summary-total');
  if (!itemsWrap || !subtotalEl || !deliveryEl || !totalEl) return;

  itemsWrap.innerHTML = '';
  const detailed = getCartDetailedItems();

  let subtotal = 0;
  detailed.forEach(({ quantity, detail }) => {
    const linePrice = (detail.price || 0) * quantity;
    subtotal += linePrice;
    const row = document.createElement('div');
    row.className = 'summary-item';
    const img = document.createElement('img');
    img.src = detail.imageUrl;
    img.alt = detail.name;
    img.loading = 'lazy';
    const info = document.createElement('div');
    const title = document.createElement('div');
    title.className = 'title';
    title.textContent = detail.name;
    const qty = document.createElement('div');
    qty.className = 'qty';
    qty.textContent = `Qty ${quantity}`;
    const line = document.createElement('div');
    line.className = 'line';
    line.textContent = formatNaira(linePrice);
    info.appendChild(title);
    info.appendChild(qty);
    row.appendChild(img);
    row.appendChild(info);
    row.appendChild(line);
    itemsWrap.appendChild(row);
  });

  const deliveryFee = 1500;
  subtotalEl.textContent = formatNaira(subtotal);
  deliveryEl.textContent = formatNaira(deliveryFee);
  totalEl.textContent = formatNaira(subtotal + deliveryFee);
}

function setupProceedHandler() {
  const proceedBtn = document.getElementById('proceed-payment');
  if (!proceedBtn) return;
  proceedBtn.addEventListener('click', () => {
    const name = document.getElementById('fullName');
    const email = document.getElementById('email');
    const phone = document.getElementById('phone');
    const address = document.getElementById('address');
    const missing = [];
    if (!name || !name.value.trim()) missing.push('Full Name');
    if (!email || !email.value.trim()) missing.push('Email Address');
    if (!phone || !phone.value.trim()) missing.push('Phone Number');
    if (!address || !address.value.trim()) missing.push('Delivery Address');
    if (missing.length > 0) {
      alert(`Please fill in: ${missing.join(', ')}`);
      return;
    }

    // Compute totals
    const detailed = getCartDetailedItems();
    let subtotal = 0;
    detailed.forEach(({ quantity, detail }) => {
      subtotal += (detail.price || 0) * quantity;
    });
    const deliveryFee = 1500;
    const totalInNaira = subtotal + deliveryFee;

    // --- Paystack Integration ---
    const PAYSTACK_PUBLIC_KEY = 'pk_test_YOUR_KEY_HERE';

    const form = document.getElementById('checkout-form');
    const emailValue = (email && email.value) ? email.value.trim() : '';
    const totalInKobo = Math.round(totalInNaira * 100);

    try {
      // Prefer new PaystackPop API if available
      const handler = (window.Paystack && (window.PaystackPop || window.Paystack).setup)
        ? (window.PaystackPop || window.Paystack).setup({
            key: PAYSTACK_PUBLIC_KEY,
            email: emailValue,
            amount: totalInKobo,
            ref: 'mamas-kitchen-' + Date.now(),
            callback: function (response) {
              // Success
              try { localStorage.removeItem('mk_cart'); } catch (_) {}
              window.location.href = 'thank-you.html';
            },
            onClose: function () {
              alert('You closed the payment window without completing your order.');
            }
          })
        : null;

      if (handler && handler.openIframe) {
        handler.openIframe();
      } else if (window.Paystack && window.Paystack.init) {
        // Fallback to older init API if present
        const inline = window.Paystack.init({
          key: PAYSTACK_PUBLIC_KEY,
          email: emailValue,
          amount: totalInKobo,
          ref: 'mamas-kitchen-' + Date.now(),
          onSuccess: function () {
            try { localStorage.removeItem('mk_cart'); } catch (_) {}
            window.location.href = 'thank-you.html';
          },
          onClose: function () {
            alert('You closed the payment window without completing your order.');
          }
        });
        inline.openIframe();
      } else {
        alert('Payment library not loaded. Please check your connection and try again.');
      }
    } catch (err) {
      alert('Unable to start payment. Please try again.');
    }
  });
}


