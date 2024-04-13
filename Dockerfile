# Start from a base Go image for building
FROM golang:latest AS builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the entire project into the container
COPY . .

# Build the corser CLI application
RUN go build -o corser ./cmd/corser

# Start a new stage from scratch
FROM alpine:latest  

# Set the Current Working Directory inside the container
WORKDIR /root/

# Copy the compiled binary from the builder stage
COPY --from=builder /app/corser /usr/local/bin/

# Command to run the corser CLI application
CMD ["corser"]
