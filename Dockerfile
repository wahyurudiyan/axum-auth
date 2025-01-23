FROM rust:1.84 AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:latest
WORKDIR /app
COPY --from=builder /app/target/release/axum-auth /app
RUN --mount=type=secret,id=paseto_private_key,target=/run/secrets/private_key.pem
RUN chmod +x axum-auth
CMD ["./axum-auth"]