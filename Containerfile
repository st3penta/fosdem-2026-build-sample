FROM alpine:latest

WORKDIR /app

# Copy the pre-built binary
COPY build-sample /app/build-sample

# Run the binary
CMD ["/app/build-sample"]
