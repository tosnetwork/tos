# The Open System

The Open System (TOS) is a fast, secure, scalable blockchain focused on handling millions of transactions per second (TPS) with the goal of reaching hundreds of millions of blockchain users.

## Actor Model

TOS is designed with the Actor Model as a first principle. Our architecture starts from the idea that the system should be composed of independent actors that own their own state, communicate through message passing, and execute without relying on shared mutable memory.

This design approach gives us a clear foundation for building a blockchain that is naturally parallel, fault-isolated, and scalable. By treating accounts, contracts, and system components as message-driven actors, TOS is structured to support high throughput, predictable execution, and modular system evolution as the network grows.

## Build

Build instructions are available in [BUILD.md](BUILD.md).
