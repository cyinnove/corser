# Start with the official Golang base image for the build stage
FROM golang:1.22.2 AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source code into the container
COPY . .

# Build the Go app as a static binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o corser ./cmd/corser

# Start new stage from scratch
FROM scratch

# Set the working directory to /root/
WORKDIR /root/

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /app/corser .

# Command to run the executable
ENTRYPOINT ["./corser"]
