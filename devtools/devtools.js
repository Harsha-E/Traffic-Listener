/**
 * NetListener - DevTools Integration
 * Creates the 'NetListener' panel inside Chrome Developer Tools.
 */

chrome.devtools.panels.create(
  'NetListener',
  'icons/icon-16.png',
  'devtools/panel.html',
  (panel) => {
    // Panel created successfully
  }
);
