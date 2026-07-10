// Deterministic stand-in for `webextension-polyfill` used only by the rendered-UI fixture bundle.
// The real polyfill throws when evaluated outside an extension; the fixture must never reach a real
// browser or worker API, so every seam here is inert. No fixture surface invokes these.
const browser = {
  permissions: {
    async request() {
      return false;
    },
  },
  runtime: {
    getManifest() {
      return { version: '0.0.0-fixture' };
    },
  },
};

export default browser;
