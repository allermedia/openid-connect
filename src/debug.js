import debug from 'debug';

/**
 * @param {string} name extend debug with name
 */
export default function Debug(name) {
  return debug('aller-openid-connect').extend(name);
}
