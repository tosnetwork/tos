/**
 * @tos-domains/protocol — client-side core for the .tos naming system.
 *
 * Authority boundary: a .tos name is an alias and discovery hint. Nothing in
 * this package creates identity, authorization, payment, or execution
 * authority; finalized TOS chain state is the only authority, and consumers
 * of Agent-native records must re-verify through their own protocols.
 */
export * from './cell.js';
export * from './address.js';
export * from './name.js';
export * from './categories.js';
export * from './item.js';
export * from './auction.js';
export * from './messages.js';
export * from './records.js';
export * from './resolve.js';
