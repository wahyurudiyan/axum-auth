# Axum Auth

Auth service using PASETO for signing and encryption that build in Rust. Delve more about PASETO [here](https://paseto.io/). For running the network app asynchronous, this project running on Tokio Asynchronous Runtime.

## Crates

The crates that used in this project:
* [Axum](https://crates.io/crates/axum): HTTP Framework to build REST API Application.
* [Tokio](https://tokio.rs/): Asynchronous Runtime.
* [Pasetors](https://crates.io/crates/pasetors): PASETO Singing.

## How to Run
This application can run with two was, using `cargo` or `docker compose`.

1. Running with Cargo
```bash
cargo run
```

2. Running with Docker Compose
```bash
docker compose up --build
```