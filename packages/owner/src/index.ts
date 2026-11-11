/**
 * @agnap/owner
 *
 * The resource owner's side of the local owner extension: an owner key on
 * disk, a client whose every request is signed with it, a plain-text view of
 * pending grants, scripted rules, and the watch loop behind `agnap-owner`.
 * Run it in a process the agent cannot reach.
 */
export * from './keys.js';
export * from './client.js';
export * from './describe.js';
export * from './rules.js';
export * from './watch.js';
