export class CustomStore {
  /** @type {Map<string, any>} */
  #store;
  constructor() {
    this.#store = new Map();
  }
  /**
   * Get value by key
   * @param {string} key
   */
  get(key) {
    const stored = this.#store.get(key);
    return Promise.resolve(stored?.content ? JSON.parse(stored.content) : null);
  }
  /**
   * Set value
   * @param {string} key
   * @param {any} value
   */
  set(key, value) {
    const content = typeof value === 'object' ? value : JSON.parse(value);

    let exp = -2;
    if (content.cookie?.expires) {
      exp = content.cookie.expires;
    } else if (content.header?.exp) {
      exp = content.header.exp;
    }

    this.#store.set(key, { exp, content: JSON.stringify(content) });
    return Promise.resolve();
  }
  /**
   * Remove keyed value
   * @param {string} key
   */
  destroy(key) {
    this.#store.delete(key);
    return Promise.resolve();
  }
  /**
   * Get ttl
   * @param {string} key
   */
  ttl(key) {
    const stored = this.#store.get(key);
    return Promise.resolve(stored?.exp > 0 ? Math.floor((stored.exp - Date.now()) / 1000) : -2);
  }
  /**
   * Get db size
   */
  dbSize() {
    return Promise.resolve(this.#store.size);
  }
}
