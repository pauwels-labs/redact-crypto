FROM debian:8
EXPOSE 8080
CMD ["/redact-crypto"]
COPY target/release/ /
