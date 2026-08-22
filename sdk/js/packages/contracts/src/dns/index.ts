/**
 * .tos naming system (TOS DNS) client core.
 *
 * Authority boundary: a .tos name is an alias and discovery hint. Nothing in
 * this module creates identity, authorization, payment, or execution
 * authority; finalized TOS chain state is the only authority, and consumers
 * of Agent-native records must re-verify through their own protocols.
 */
export * from './name';
export * from './categories';
export * from './item';
export * from './auction';
export * from './messages';
export * from './records';
export * from './resolve';
